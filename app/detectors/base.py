# app/detectors/base.py
from typing import Dict, Any, List

def make_result(score: int, reasons: List[str] | None = None,
                blocked: List[str] | None = None, style: Dict[str, Any] | None = None,
                hard_block: bool = False) -> Dict[str, Any]:
    """
    Return a standard detector result dict.
    hard_block: when True -> this code should be outright blocked (no execution).
    """
    return {
        "score": max(0, min(100, score)),
        "reasons": reasons or [],
        "blocked": blocked or [],
        "style": style or {},
        "hard_block": bool(hard_block),
    }
