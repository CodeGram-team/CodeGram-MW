# app/detectors/python_rules.py
import re
import ast
from typing import Dict, Any, List
from app.detectors.base import make_result
from app.utils import comment_ratio, avg_function_len_python

# 기존 규칙 유지 + 설명
GENERIC_FORBIDDEN = [
    (r"\b(eval|exec)\b", 35, "동적 코드 실행"),
    (r"\b(subprocess|Popen|system\()\b", 30, "프로세스 실행"),
    (r"\b(socket\.|requests\.|httpx\.)", 10, "네트워크 접근"),
    (r"while\s*True\s*:", 10, "무한루프 의심(정적 패턴)"),
    (r"\bos\.fork\b", 40, "포크 폭탄 위험"),
    (r"__import__\(", 25, "우회 임포트"),
    (r"\b(ctypes\.|cffi\.)", 25, "네이티브 호출"),
]

PY_FORBIDDEN_IMPORTS = {
    "subprocess": 35, "socket": 12, "os": 8, "sys": 6, "multiprocessing": 14,
    "threading": 8, "httpx": 8, "requests": 8, "ctypes": 25
}

# 추가: 무한루프에 대하여는 하드블록 처리(우회가능성은 있지만 우선 안전 우선)
def analyze_python(code: str) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    blocked: List[str] = []
    hard_block = False

    # 1) 정적(텍스트) 패턴: while True / while 1 등
    if re.search(r"\bwhile\s+(True|1)\s*:", code):
        reasons.append("무한루프(정적 패턴)")
        blocked.append("infinite-loop")
        score += 80
        hard_block = True

    # 2) 기존 generic regex 탐지
    for pattern, pts, msg in GENERIC_FORBIDDEN:
        if re.search(pattern, code, flags=re.MULTILINE):
            # 이미 무한루프 하드블록이면 추가 점수는 필요 없음, 다만 이유/blocked 채우기
            if "무한루프" not in msg:
                reasons.append(msg)
                blocked.append(msg)
                score += pts

    # 3) AST 기반 정밀 탐지 (if possible)
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            # imports -> 위험 모듈 점수
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod in PY_FORBIDDEN_IMPORTS:
                        pts = PY_FORBIDDEN_IMPORTS[mod]
                        score += pts
                        reasons.append(f"위험 모듈: {mod}")
                        blocked.append(f"no-{mod}")

            # call에서 eval/exec 탐지
            elif isinstance(node, ast.Call):
                fn = None
                # 여러 형태의 call.func 추출
                if isinstance(node.func, ast.Name):
                    fn = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fn = node.func.attr
                if fn in {"eval", "exec"}:
                    score += 30
                    reasons.append(f"동적 실행 함수: {fn}")
                    blocked.append(f"no-{fn}")

            # AST 수준 무한루프 감지 (조건이 constant True)
            elif isinstance(node, ast.While):
                cond = node.test
                # Python3.8+ ast.Constant
                is_const_true = False
                if isinstance(cond, ast.Constant) and cond.value is True:
                    is_const_true = True
                # older ast.NameConstant
                elif getattr(ast, "NameConstant", None) and isinstance(cond, ast.NameConstant) and cond.value is True:
                    is_const_true = True
                if is_const_true:
                    reasons.append("무한루프(AST 조건 감지)")
                    blocked.append("infinite-loop")
                    score += 80
                    hard_block = True

    except Exception:
        # AST 파싱 실패는 의심스럽게 처리
        score += 20
        reasons.append("AST 파싱 실패")

        # keep tree = None for style calculation
        tree = None

    # style metrics
    style = {
        "comment_ratio": round(comment_ratio(code), 3),
        "avg_function_length": round(avg_function_len_python(tree) if tree else 0.0, 1),
    }

    # clamp & return with hard_block flag
    return make_result(score, reasons, list(sorted(set(blocked))), style, hard_block=hard_block)
