from typing import Dict, Any, List

def make_result(score: int, reasons: List[str] | None = None,
                blocked: List[str] | None = None, style: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {
        "score": max(0, min(100, score)),
        "reasons": reasons or [],
        "blocked": blocked or [],
        "style": style or {},
    }
