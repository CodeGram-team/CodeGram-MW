from fastapi import FastAPI, HTTPException
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.detectors.lang_detect import detect_language
from app.detectors.python_rules import analyze_python
from app.detectors.generic_rules import analyze_generic
from app.emoji.tagger import map_emojis
from app.scoring import decision_logic, suggest_limits

APP_VERSION = "mvp-0.1.0"
app = FastAPI(title="Malware & Emoji Tagging Service", version=APP_VERSION)

@app.get("/health")
def health():
    return {"ok": True, "version": APP_VERSION}

@app.post("/v1/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    if not req.code.strip():
        raise HTTPException(400, "Empty code string")
    lang = detect_language(req.code, req.language)
    result = analyze_python(req.code) if lang == "python" else analyze_generic(req.code)
    emoji = map_emojis(req.code)
    decision, safe = decision_logic(result["score"])
    limits = suggest_limits(result["score"], lang)
    return AnalyzeResponse(
        safe=safe,
        risk_score=result["score"],
        decision=decision,
        language=lang,
        blocked_rules=result.get("blocked", []),
        reasons=result.get("reasons", []),
        suggested_limits=limits,
        emojis=emoji["emojis"],
        emoji_labels=emoji["emoji_labels"],
        tags=emoji["tags"],
        style=result.get("style", {}),
        version=APP_VERSION,
    )
