from pydantic import BaseModel, Field
from typing import List, Dict, Any

class AnalyzeRequest(BaseModel):
    # Received payload: only code text and optional language hint.
    code: str = Field(..., min_length=1, description="Source code text (UTF-8)")
    language: str = Field("auto", description="Language hint: 'auto' or e.g. 'python', 'javascript'")

class AnalyzeResponse(BaseModel):
    safe: bool
    risk_score: int
    decision: str
    language: str
    blocked_rules: List[str] = []
    reasons: List[str] = []
    suggested_limits: Dict[str, int] = {}
    # Emoji fields: make defaults so missing values won't cause ValidationError
    emoji_ids: List[str] = []
    emojis: List[str] = []
    emoji_labels: List[str] = []
    tags: List[str] = []
    style: Dict[str, Any] = {}
    scores: Dict[str, float] = {}
    version: str
