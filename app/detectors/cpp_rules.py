# app/detectors/cpp_rules.py
import re
from typing import Dict, Any
from app.detectors.base import make_result
from app.detectors.resource_utils import run_all_resource_checks

CPP_FORBIDDEN = [
    (r"\bsystem\s*\(", 35, "system() 호출"),
    (r"\bpopen\s*\(", 35, "popen() 호출"),
    (r"\bstd::thread\b", 12, "std::thread 사용 (스레드)"),
    (r"\bmalloc\s*\(", 20, "malloc 호출"),
]

def analyze_cpp(code: str) -> Dict[str, Any]:
    score = 0; reasons = []; blocked = []
    for pat, pts, msg in CPP_FORBIDDEN:
        if re.search(pat, code, flags=re.IGNORECASE):
            score += pts; reasons.append(msg)
            if "system" in msg.lower():
                blocked.append("no-system-call")
    r_score, r_reasons, r_blocked = run_all_resource_checks(code)
    score += r_score; reasons.extend(r_reasons); blocked.extend(r_blocked)
    return make_result(score, reasons, list(sorted(set(blocked))))
