import re
from app.detectors.base import make_result

GENERIC_FORBIDDEN = [
    (r"\b(eval|exec)\b", 30, "동적 코드 실행"),
    (r"\b(fork|system\()\b", 25, "프로세스 제어"),
]

def analyze_generic(code: str):
    score, reasons = 0, []
    for pattern, pts, msg in GENERIC_FORBIDDEN:
        if re.search(pattern, code, flags=re.MULTILINE):
            score += pts; reasons.append(msg)
    return make_result(score, reasons)
