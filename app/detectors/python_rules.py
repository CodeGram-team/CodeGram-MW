import re, ast
from typing import Dict, Any, List
from app.detectors.base import make_result
from app.utils import comment_ratio, avg_function_len_python

# 기존 규칙들 + 무한루프 탐지 강화
GENERIC_FORBIDDEN = [
    (r"\b(eval|exec)\b", 35, "동적 코드 실행"),
    (r"\b(subprocess|Popen|system\()\b", 30, "프로세스 실행"),
    (r"\b(socket\.|requests\.|httpx\.)", 10, "네트워크 접근"),
    (r"\bwhile\s*True\b", 20, "무한루프(정적 패턴)"),
    (r"\bos\.fork\b", 40, "포크 폭탄 위험"),
    (r"__import__\(", 25, "우회 임포트"),
    (r"\b(ctypes\.|cffi\.)", 25, "네이티브 호출"),
]

PY_FORBIDDEN_IMPORTS = {
    "subprocess": 35, "socket": 12, "os": 8, "sys": 6, "multiprocessing": 14,
    "threading": 8, "httpx": 8, "requests": 8, "ctypes": 25
}

# helper: 검사할 AST body에서 'exit' 구문(직접 루프를 끝낼 수 있는) 존재 여부 검사
def _body_has_exit_statements(stmts: List[ast.stmt]) -> bool:
    """
    주의: 함수/클래스 정의 내부는 '루프 외부'로 간주하고 탐색을 건너뜀.
    재귀적으로 If/For/While/Try/With의 body/orelse/finalbody를 검사.
    """
    for node in stmts:
        # 직접적인 탈출문
        if isinstance(node, (ast.Break, ast.Return, ast.Raise)):
            return True

        # sys.exit(), exit(), quit() 와 같은 호출 감지
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            func = call.func
            if isinstance(func, ast.Name) and func.id in ("exit", "quit"):
                return True
            if isinstance(func, ast.Attribute) and func.attr in ("exit", "abort", "terminate"):
                # ex) sys.exit()
                return True

        # 제어구조 내부 재귀 검사 (하지만 함수/클래스 정의는 건너뜀)
        if isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            # If: check body and orelse
            inner_bodies = []
            if hasattr(node, "body"):
                inner_bodies.append(node.body)
            if hasattr(node, "orelse"):
                inner_bodies.append(node.orelse)
            if isinstance(node, ast.Try):
                # handlers and finalbody,orelse
                for h in node.handlers:
                    inner_bodies.append(h.body)
                if node.finalbody:
                    inner_bodies.append(node.finalbody)
            for b in inner_bodies:
                if _body_has_exit_statements(b):
                    return True

        # skip nested function/class definitions (they don't break the loop)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue

    return False

def _is_constant_true_test(test_node: ast.AST) -> bool:
    # Python 3.8+: ast.Constant(value=True)
    if isinstance(test_node, ast.Constant):
        return bool(test_node.value) is True
    # NameConstant older python
    if getattr(ast, "NameConstant", None) and isinstance(test_node, ast.NameConstant):
        return bool(test_node.value) is True
    # numeric literal 1 in while 1:
    if isinstance(test_node, ast.Num):
        return test_node.n == 1
    # could also be "True" name (rare if True is name)
    if isinstance(test_node, ast.Name) and test_node.id == "True":
        return True
    return False

def _detect_infinite_loops_in_ast(tree: ast.AST) -> List[str]:
    """
    AST 기반 무한루프 탐지:
     - while True / while 1 형태이며 루프 본문에 탈출구가 없으면 무한루프 위험
     - for ... in itertools.count(...) 형태 탐지
    반환: 리스트(이유 문구)
    """
    reasons = []
    for node in ast.walk(tree):
        # while True / while 1
        if isinstance(node, ast.While):
            if _is_constant_true_test(node.test):
                # check loop body for any exit statements
                if not _body_has_exit_statements(node.body):
                    reasons.append("무한루프 탐지: constant True while without exit")
        # for ... in itertools.count()
        if isinstance(node, ast.For):
            # check iter is Call to something named 'count' or 'itertools.count'
            it = node.iter
            if isinstance(it, ast.Call):
                func = it.func
                fname = None
                if isinstance(func, ast.Attribute):
                    fname = func.attr
                elif isinstance(func, ast.Name):
                    fname = func.id
                if fname == "count":
                    # 추가: check if import shows itertools (best-effort not perfect)
                    reasons.append("무한루프 탐지: for in 'count()' (무한 반복 가능성)")
        # iter(callable, sentinel) pattern (ex: iter(int, 1)) -> can be infinite if callable never returns sentinel
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "iter":
            # iter(callable, sentinel)
            if len(node.args) == 2:
                reasons.append("무한루프 탐지: iter(callable, sentinel) 패턴 (무한 반복 가능성)")
    return reasons

def analyze_python(code: str) -> Dict[str, Any]:
    score, reasons, blocked = 0, [], []

    # regex quick checks
    for pattern, pts, msg in GENERIC_FORBIDDEN:
        if re.search(pattern, code, flags=re.MULTILINE):
            score += pts
            reasons.append(msg)

    try:
        tree = ast.parse(code)
        # AST-based checks
        # 1) forbidden imports / calls
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod in PY_FORBIDDEN_IMPORTS:
                        score += PY_FORBIDDEN_IMPORTS[mod]
                        reasons.append(f"위험 모듈: {mod}")
                        blocked.append(f"no-{mod}")
            elif isinstance(node, ast.Call):
                # detect eval/exec
                fn = None
                if isinstance(node.func, ast.Name):
                    fn = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fn = node.func.attr
                if fn in {"eval", "exec"}:
                    score += 30
                    reasons.append(f"동적 실행 함수: {fn}")
        # 2) infinite loop detection (AST)
        inf_reasons = _detect_infinite_loops_in_ast(tree)
        if inf_reasons:
            # 강력 차단: 높은 점수와 blocked rule 추가
            score += 90
            for r in inf_reasons:
                reasons.append(r)
            blocked.append("infinite-loop")
    except Exception:
        score += 5
        reasons.append("AST 파싱 실패")
        tree = None

    style = {
        "comment_ratio": round(comment_ratio(code), 3),
        "avg_function_length": round(avg_function_len_python(tree) if tree else 0.0, 1),
    }
    return make_result(score, reasons, list(sorted(set(blocked))), style)