# app/detectors/java_rules.py
import re
from typing import Dict, Any
from app.detectors.base import make_result
from app.detectors.resource_utils import run_all_resource_checks

JAVA_FORBIDDEN = [
    (r"Runtime\.getRuntime\(\)\.exec\s*\(", 45, "Runtime.exec 호출"),
    (r"new\s+ProcessBuilder\s*\(", 40, "ProcessBuilder 사용"),
    (r"\bServerSocket\b", 30, "서버 소켓 (수신)"),
    (r"\bThread\s*\(", 12, "Thread 사용 (스레드 생성)"),
]

def analyze_java(code: str) -> Dict[str, Any]:
    score = 0; reasons = []; blocked = []
    for pat, pts, msg in JAVA_FORBIDDEN:
        if re.search(pat, code):
            score += pts; reasons.append(msg)
            if "exec" in msg.lower() or "processbuilder" in msg.lower():
                blocked.append("no-exec")
    r_score, r_reasons, r_blocked = run_all_resource_checks(code)
    score += r_score; reasons.extend(r_reasons); blocked.extend(r_blocked)
    return make_result(score, reasons, list(sorted(set(blocked))))
