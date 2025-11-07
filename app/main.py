from fastapi import FastAPI, HTTPException
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.detectors.lang_detect import detect_language
from app.detectors.python_rules import analyze_python
from app.detectors.generic_rules import analyze_generic
# Emoji/tagger imports
from app.emoji.tagger import map_emojis
from app.emoji.openai_tagger import get_openai_emojis_safe
from app.scoring import decision_logic, suggest_limits

APP_VERSION = "mvp-0.1.0"
app = FastAPI(title="Malware & Emoji Tagging Service", version=APP_VERSION)

@app.get("/health")
def health():
    return {"ok": True, "version": APP_VERSION}

@app.post("/v1/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    if not req.code or not req.code.strip():
        raise HTTPException(400, "Empty code string")

    # 언어 감지 및 정적 분석(언어별)
    lang = detect_language(req.code, req.language)
    result = analyze_python(req.code) if lang == "python" else analyze_generic(req.code)

    # 이모지 태깅: OpenAI 시도 -> 실패 시 로컬 태거로 폴백
    try:
        emoji_res = get_openai_emojis_safe(req.code, local_fallback_callable=map_emojis)
        # ensure fields exist
        emoji_ids = emoji_res.get("emoji_ids", [])
        emojis = emoji_res.get("emojis", [])
        emoji_labels = emoji_res.get("emoji_labels", [])
        fallback_used = bool(emoji_res.get("fallback_used", False))
        openai_usage = emoji_res.get("openai_usage", None)
        scores = emoji_res.get("scores", {}) if isinstance(emoji_res, dict) else {}
    except Exception as e:
        # 로깅은 서버 로그로 (uvicorn 터미널) 찍히게 하자
        import logging
        logging.exception("Emoji tagging failed, using local map_emojis fallback: %s", e)
        local = map_emojis(req.code)
        # local map_emojis returns {emojis, emoji_labels, tags} in original impl
        emoji_ids = local.get("emoji_ids", []) or []
        emojis = local.get("emojis", []) or local.get("emoji_ids", []) or []
        emoji_labels = local.get("emoji_labels", []) or []
        fallback_used = True
        openai_usage = None
        scores = {}

    # 의사결정 + suggested limits
    decision, safe = decision_logic(result["score"])
    limits = suggest_limits(result["score"], lang)

    # 반환: AnalyzeResponse 스키마에 맞춰 반환 (필드 이름은 schemas.py에 맞춰 조정)
    return AnalyzeResponse(
        safe=safe,
        risk_score=result["score"],
        decision=decision,
        language=lang, 
        blocked_rules=result.get("blocked", []),
        reasons=result.get("reasons", []),
        suggested_limits=limits,
        emojis=emojis,
        emoji_labels=emoji_labels,
        emoji_ids=emoji_ids,          # 새로 추가된 필드: emoji_ids
        tags=result.get("tags", []),
        style=result.get("style", {}),
        scores=scores,
        version=APP_VERSION,
        fallback_used=fallback_used,  # 새로 추가된 필드: fallback_used
        openai_usage=openai_usage     # 새로 추가된 필드: openai_usage
    )
