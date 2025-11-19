# app/detectors/resource_utils.py
import re
from typing import Tuple, List

# 무한루프/루프 관련 패턴
INFINITE_LOOP_PATTERNS = [
    r"\bwhile\s*\(\s*1\s*\)",            # C/C++/Java: while(1)
    r"\bfor\s*\(\s*;\s*;\s*\)",          # C/C++/Java: for(;;)
    r"\bwhile\s+True\s*:",               # Python: while True:
    r"\bdo\s*\{[\s\S]*?\}\s*while\s*\(1\)", # do{ } while(1)
]

# 대량할당 패턴 (거친 추정: 숫자 1,000,000 이상 등)
LARGE_ALLOC_PATTERNS = [
    r"\bmalloc\s*\(\s*([0-9]{6,})\s*\)",
    r"\bcalloc\s*\(\s*([0-9]{6,})\s*,",
    r"new\s+[a-zA-Z_0-9:<>]+\s*\[\s*([0-9]{6,})\s*\]",
    r"\bstd::vector<[^>]+>\s*\w+\s*\(\s*([0-9]{6,})\s*\)",
    r"\b(np|numpy)\.(zeros|ones|empty)\s*\(\s*\(?\s*([0-9]{4,})",
    r"\bbytearray\s*\(\s*([0-9]{6,})\s*\)",
]

# 반복문 내부의 I/O 패턴 (파일/네트워크 반복)
IO_IN_LOOP_SNIPPET = r"(while|for)[\s\S]{0,600}?(read|fread|fgets|fscanf|write|send|recv|readline|readlines|readinto|fs\.write|fs\.writeFile|writeFileSync|writeFile)\s*\("

# 프로세스/스레드/외부명령
PROCESS_THREAD_PATTERNS = [
    r"\bfork\s*\(",
    r"\bexec(v|ve|vp|vpe)?\s*\(",
    r"\bsystem\s*\(",
    r"\bThread\s*\(",
    r"\bstd::thread\b",
    r"child_process\.(exec|spawn|fork|execSync|spawnSync)",
    r"Runtime\.getRuntime\(\)\.exec\s*\(",
    r"new\s+ProcessBuilder\s*\(",
    r"\bsubprocess\.(Popen|call|run|check_output)\s*\(",
]

# 파일 쓰기/삭제/이동 등 위험 패턴
FILE_WRITE_PATTERNS = [
    r"\bfopen\s*\([^\)]*['\"]w['\"]",
    r"\bofstream\b",
    r"\bopen\([^,]+,[^)]*['\"]w['\"]",
    r"\bfs\.(writeFile|writeFileSync|appendFile|unlink|rm)\b",
    r"\bFiles\.(write|delete|move)\b",
    r"\bopen\([^,]+,[^)]*['\"]wb['\"]",
]

# 간단한 재귀 탐지 (파이썬용 heuristic)
RECURSION_SNIPPET = r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*\):[\s\S]{0,400}\1\s*\("

def detect_infinite_loop(code: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    for p in INFINITE_LOOP_PATTERNS:
        if re.search(p, code, flags=re.IGNORECASE):
            score += 40
            reasons.append("무한루프(정적 패턴): " + p)
    if re.search(r"\bwhile\b|\bfor\b", code) and not re.search(r"\bbreak\b", code):
        score += 5
        reasons.append("반복문에서 break/중단 키워드 미검출 — 잠재적 장시간 실행")
    return score, reasons

def detect_large_alloc(code: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    for p in LARGE_ALLOC_PATTERNS:
        m = re.search(p, code, flags=re.IGNORECASE)
        if m:
            digits = None
            for g in (m.groups() or []):
                if g and g.isdigit():
                    digits = int(g)
                    break
            if digits and digits >= 10**6:
                score += 35
                reasons.append(f"대규모 메모리 할당 탐지: {digits} 바이트 이상")
            else:
                score += 10
                reasons.append("메모리 할당 패턴 탐지 (잠재적 대량 할당)")
    return score, reasons

def detect_io_in_loop(code: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    if re.search(IO_IN_LOOP_SNIPPET, code, flags=re.IGNORECASE):
        score += 25
        reasons.append("반복문 내부의 반복적 I/O 패턴(파일/네트워크) — 장시간 I/O 가능")
    writes = len(re.findall(r"\b(write|send|recv|fwrite|fputs|fprintf|fs\.write|writeFileSync)\b", code, flags=re.IGNORECASE))
    if writes >= 6:
        score += 10
        reasons.append(f"빈번한 I/O 호출 패턴 탐지 (count={writes})")
    return score, reasons

def detect_proc_thread_spawn(code: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    for p in PROCESS_THREAD_PATTERNS:
        if re.search(p, code, flags=re.IGNORECASE):
            score += 30
            reasons.append("프로세스/스레드 생성 또는 외부명령 호출: " + p)
    return score, reasons

def detect_file_write_patterns(code: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    for p in FILE_WRITE_PATTERNS:
        if re.search(p, code, flags=re.IGNORECASE):
            score += 15
            reasons.append("파일 쓰기/삭제/이동 패턴 탐지: " + p)
    return score, reasons

def detect_recursion(code: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    if re.search(RECURSION_SNIPPET, code):
        score += 20
        reasons.append("재귀 호출 패턴 탐지 (탈출조건 미존재 가능성)")
    return score, reasons

def run_all_resource_checks(code: str) -> Tuple[int, List[str], List[str]]:
    total = 0
    reasons = []
    blocked = []
    for f in (detect_infinite_loop, detect_large_alloc, detect_io_in_loop, detect_proc_thread_spawn, detect_file_write_patterns, detect_recursion):
        s, r = f(code)
        if s:
            total += s
            reasons.extend(r)
    if re.search(r"\b(exec|system|popen|Runtime\.getRuntime|child_process\.)\b", code, flags=re.IGNORECASE):
        blocked.append("no-exec")
    if re.search(r"\bfork\b|\bspawn\b", code, flags=re.IGNORECASE):
        blocked.append("no-fork")
    if re.search(r"\bmalloc\b|\bcalloc\b|\bnew\s+[^\s]+\s*\[", code, flags=re.IGNORECASE):
        blocked.append("no-large-alloc")
    return max(0, min(100, total)), reasons, blocked