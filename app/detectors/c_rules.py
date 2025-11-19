# app/detectors/c_rules.py
import re
from typing import Dict, Any
from app.detectors.base import make_result
from app.detectors.resource_utils import run_all_resource_checks

C_FORBIDDEN = [
    (r"\bsystem\s*\(", 35, "system() 호출 (명령 실행)"),
    (r"\bpopen\s*\(", 35, "popen() (명령 실행)"),
    (r"\b(socket\s*\(|accept\s*\(|recv\s*\()", 20, "네트워크/소켓 사용"),
    (r"\bfork\s*\(", 40, "포크 위험"),
    (r"\bexec(v|ve|vp|vpe)?\s*\(", 45, "exec 계열 호출"),
    (r"\bptrace\s*\(", 40, "프로세스 제어 위험"),
]

def analyze_c(code: str) -> Dict[str, Any]:
    score = 0; reasons = []; blocked = []
    for pat, pts, msg in C_FORBIDDEN:
        if re.search(pat, code, flags=re.IGNORECASE):
            score += pts; reasons.append(msg)
            if "exec" in msg.lower() or "fork" in msg.lower():
                blocked.append("no-system-call")
    r_score, r_reasons, r_blocked = run_all_resource_checks(code)
    score += r_score; reasons.extend(r_reasons); blocked.extend(r_blocked)
    return make_result(score, reasons, list(sorted(set(blocked))))
