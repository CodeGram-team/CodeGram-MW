# app/emoji/openai_tagger.py
import os
import json
import re
import hashlib
import time
import logging
from typing import Dict, Any, List, Optional

# logging config (library-level; 실제 서비스에서는 로거 설정을 중앙에서 관리하는 것을 권장)
logger = logging.getLogger("openai_tagger")
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(ch)
logger.setLevel(logging.INFO)

# OpenAI SDK import (support variations)
try:
    from openai import OpenAI
    import openai as _openai
    openai_error = getattr(_openai, "error", Exception)
except Exception as e:
    # If the SDK is missing the module-level 'error', we still want to import OpenAI when available.
    # But if import fails completely, we will raise: callers will catch and fallback locally.
    try:
        from openai import OpenAI  # try again for clarity
        import openai as _openai
        openai_error = getattr(_openai, "error", Exception)
    except Exception:
        raise RuntimeError("OpenAI SDK is required. Install with `pip install openai`") from e

# Create client if API key present; allow absence so callers can fallback
_API_KEY = os.environ.get("OPENAI_API_KEY")
_client = OpenAI(api_key=_API_KEY) if _API_KEY else None

# Allowed emoji list (30 items) - id,label,emoji
ALLOWED_EMOJI = [
  {"id":"toss_star","label":"stars","emoji":"⭐"},
  {"id":"toss_ascii","label":"ascii_art","emoji":"🖼️"},
  {"id":"toss_chart","label":"chart","emoji":"📈"},
  {"id":"toss_table","label":"table","emoji":"📊"},
  {"id":"toss_data","label":"data_processing","emoji":"🧪"},
  {"id":"toss_ml","label":"machine_learning","emoji":"🤖"},
  {"id":"toss_dl","label":"deep_learning","emoji":"🧠"},
  {"id":"toss_web","label":"web","emoji":"🌐"},
  {"id":"toss_api","label":"api","emoji":"🔌"},
  {"id":"toss_db","label":"database","emoji":"🛢️"},
  {"id":"toss_io","label":"io","emoji":"📎"},
  {"id":"toss_sys","label":"system","emoji":"🛠️"},
  {"id":"toss_net","label":"networking","emoji":"🔗"},
  {"id":"toss_crypto","label":"crypto","emoji":"🔐"},
  {"id":"toss_async","label":"async","emoji":"⚡"},
  {"id":"toss_test","label":"testing","emoji":"✅"},
  {"id":"toss_algo","label":"algorithm","emoji":"⚙️"},
  {"id":"toss_math","label":"math","emoji":"➗"},
  {"id":"toss_visual","label":"ui_visual","emoji":"🎨"},
  {"id":"toss_game","label":"game","emoji":"🎮"},
  {"id":"toss_devops","label":"devops","emoji":"🔧"},
  {"id":"toss_monitor","label":"monitoring","emoji":"📡"},
  {"id":"toss_stream","label":"stream","emoji":"🔁"},
  {"id":"toss_regex","label":"parsing","emoji":"🔍"},
  {"id":"toss_image","label":"image","emoji":"🖼️"},
  {"id":"toss_audio","label":"audio","emoji":"🎧"},
  {"id":"toss_robot","label":"automation","emoji":"🤖"},
  {"id":"toss_security","label":"security","emoji":"🛡️"},
  {"id":"toss_text","label":"nlp","emoji":"📝"},
  {"id":"toss_fun","label":"fun_snippet","emoji":"😄"},
]
ALLOWED_IDS = {e["id"] for e in ALLOWED_EMOJI}

PROMPT_TEMPLATE = """
You are a code analyst. NEVER execute the code. Return exactly one JSON object.

Allowed emoji list (id,label,emoji):
{allowed_json}

Output exactly this schema:
{{
  "emoji_ids": ["<id>", ...],
  "emoji_labels": ["<label>", ...],
  "emojis": ["<unicode>", ...],
  "reasons": ["short reason", ...],
  "confidence": "low|medium|high"
}}

Rules:
- Only use ids from the allowed list. If none apply, return empty arrays.
- Prefer output/ASCII-art signals when present.
- If confident, return at least 2 emoji_ids. If not confident, return 1 and confidence "low".
- JSON only, no extra text.

Analyze code between ===CODE_START=== and ===CODE_END=== and return only the JSON.
===CODE_START===
{code}
===CODE_END===
"""

# simple redaction for common secret-like tokens
SECRET_PATTERNS = [
    r"(?:API_KEY|SECRET|TOKEN)(\s*[:=]\s*)[\"']?[^\"'\s]+[\"']?",
    r"(?i)password(\s*[:=]\s*)[\"']?[^\"'\s]+[\"']?",
    r"(?i)aws_access_key_id(\s*[:=]\s*)[\"']?[^\"'\s]+[\"']?",
    r"(?i)aws_secret_access_key(\s*[:=]\s*)[\"']?[^\"'\s]+[\"']?"
]

def mask_secrets(code: str) -> str:
    s = code
    for pat in SECRET_PATTERNS:
        s = re.sub(pat, r"\1\"<REDACTED>\"", s)
    return s

def _extract_first_json(text: str) -> Optional[str]:
    """Return the first balanced JSON object substring in text, or None."""
    if not text:
        return None
    # remove code fences that might wrap the JSON
    text = re.sub(r"```(?:json|text|bash)?\n?", "", text, flags=re.IGNORECASE).strip()
    start = text.find("{")
    if start == -1:
        return None
    stack = 0
    for i in range(start, len(text)):
        c = text[i]
        if c == "{":
            stack += 1
        elif c == "}":
            stack -= 1
            if stack == 0:
                return text[start:i+1]
    return None

def _resp_text_from_response(resp) -> Optional[str]:
    """Robustly extract textual output from OpenAI Responses object."""
    text = getattr(resp, "output_text", None)
    if text:
        return text
    out = getattr(resp, "output", None) or []
    # older/newer SDKs may structure output differently
    pieces = []
    try:
        for item in out:
            # item might be dict-like with content list
            if isinstance(item, dict):
                cont = item.get("content", [])
                for c in cont:
                    if c.get("type") == "output_text":
                        pieces.append(c.get("text", ""))
            # or item may be object with .content attribute
            else:
                cont = getattr(item, "content", None)
                if cont:
                    for c in cont:
                        t = c.get("text") if isinstance(c, dict) else getattr(c, "text", None)
                        if t:
                            pieces.append(t)
    except Exception:
        pass
    return "".join(pieces) if pieces else None

def ask_gpt_for_emojis(code: str, model: str = "gpt-5-mini", timeout: int = 20, max_output_tokens: int = 800) -> Dict[str, Any]:
    """
    Call OpenAI Responses API (gpt-5-mini) with prompt and return validated emoji dict.
    Raises exception if call fails — callers should handle fallback.
    """
    if _client is None:
        raise RuntimeError("OpenAI client not configured (OPENAI_API_KEY missing)")

    # cache by sha256 of original code (not redacted one)
    h = hashlib.sha256(code.encode("utf-8")).hexdigest()
    cache_path = f"/tmp/emoji_cache_{h}.json"
    if os.path.exists(cache_path):
        try:
            data = json.load(open(cache_path, "r", encoding="utf-8"))
            logger.info("Cache hit for code hash=%s", h)
            return data
        except Exception:
            logger.warning("Cache read failed for %s, continuing", cache_path)

    prompt = PROMPT_TEMPLATE.format(allowed_json=json.dumps(ALLOWED_EMOJI, ensure_ascii=False), code=mask_secrets(code))

    last_exc = None
    for attempt in range(3):
        try:
            logger.info("OpenAI: calling model=%s for code hash=%s with max_output_tokens=%d", model, h, max_output_tokens)
            resp = _client.responses.create(
                model=model,
                input=prompt,
                max_output_tokens=max_output_tokens,
                timeout=timeout,
            )
            # extract text robustly
            text = _resp_text_from_response(resp)
            logger.info("OpenAI: collected text length=%s for hash=%s incomplete=%s", len(text) if text else 0, h, getattr(resp, "incomplete_details", None) is not None)
            if not text:
                raise RuntimeError("No textual output from model")
            # try to find first JSON object in text
            json_snip = _extract_first_json(text)
            obj = None
            if json_snip:
                try:
                    obj = json.loads(json_snip)
                except Exception:
                    # try raw text
                    try:
                        obj = json.loads(text)
                    except Exception:
                        raise RuntimeError("Failed to parse JSON from model output")
            else:
                # fallback: try to parse whole text
                try:
                    obj = json.loads(text)
                except Exception:
                    raise RuntimeError("No JSON object found in model output")

            # validate ids and shape
            ids = [i for i in obj.get("emoji_ids", []) if i in ALLOWED_IDS]
            labels = obj.get("emoji_labels", [])[:len(ids)]
            emojis = obj.get("emojis", [])[:len(ids)]
            reasons = obj.get("reasons", [])[:len(ids)]
            confidence = obj.get("confidence", "low")

            # extract usage if present on resp
            usage = getattr(resp, "usage", None)
            usage_dict = None
            if usage:
                try:
                    # usage may be object-like or dict-like
                    usage_dict = {
                        "input_tokens": getattr(usage, "input_tokens", None) or usage.get("input_tokens", None) if isinstance(usage, dict) else getattr(usage, "input_tokens", None),
                        "output_tokens": getattr(usage, "output_tokens", None) or usage.get("output_tokens", None) if isinstance(usage, dict) else getattr(usage, "output_tokens", None),
                        "total_tokens": getattr(usage, "total_tokens", None) or usage.get("total_tokens", None) if isinstance(usage, dict) else getattr(usage, "total_tokens", None),
                    }
                except Exception:
                    usage_dict = None

            res = {
                "emoji_ids": ids,
                "emoji_labels": labels,
                "emojis": emojis,
                "reasons": reasons,
                "confidence": confidence,
                "openai_usage": usage_dict,
            }

            # minimal post-check & cache
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(res, f, ensure_ascii=False)
            except Exception:
                logger.warning("Failed to write cache %s", cache_path)

            logger.info("OpenAI: returned %d emoji_ids for code hash=%s", len(ids), h)
            logger.info("OpenAI usage: %s", usage_dict)
            return res

        except Exception as e:
            last_exc = e
            logger.exception("OpenAI call attempt %d failed for hash=%s: %s", attempt + 1, h, e)
            time.sleep(1 + attempt * 2)
            continue

    # If we reach here, raise the last exception for caller to handle fallback
    raise last_exc

def get_openai_emojis_safe(code: str, local_fallback_callable=None) -> Dict[str, Any]:
    """
    Try model; on failure, use local_fallback_callable(code) if provided to return local suggestions.
    Always returns a dict containing:
      - emoji_ids, emoji_labels, emojis, reasons, confidence
      - openai_usage (dict or None)
      - fallback_used (bool)
    """
    # Try OpenAI first
    try:
        res = ask_gpt_for_emojis(code)
        # mark origin
        if isinstance(res, dict):
            res.setdefault("fallback_used", False)
        # If not enough results, merge from local fallback
        if len(res.get("emoji_ids", [])) < 2 and callable(local_fallback_callable):
            local = local_fallback_callable(code) or {}
            added = 0
            for i, lab in enumerate(local.get("emoji_labels", [])):
                eid = (local.get("emoji_ids", []) or [])[i] if i < len(local.get("emoji_ids", [])) else None
                if eid and eid not in res["emoji_ids"]:
                    res["emoji_ids"].append(eid)
                    res["emoji_labels"].append(lab)
                    res["emojis"].append((local.get("emojis", []) or [])[i] if i < len(local.get("emojis", [])) else "")
                    res["reasons"].append("local-fallback")
                    added += 1
                if len(res["emoji_ids"]) >= 2:
                    break
            if added:
                res["fallback_used"] = False  # still originated from OpenAI but supplemented
        return res
    except Exception as e:
        logger.exception("OpenAI tagging failed, falling back to local tagger: %s", e)
        if callable(local_fallback_callable):
            lf = local_fallback_callable(code) or {}
            res = {
                "emoji_ids": lf.get("emoji_ids", []),
                "emoji_labels": lf.get("emoji_labels", []),
                "emojis": lf.get("emojis", []),
                "reasons": lf.get("reasons", []),
                "confidence": "low",
                "openai_usage": None,
                "fallback_used": True,
            }
            return res
        # if no fallback callable, return empty structure
        return {
            "emoji_ids": [],
            "emoji_labels": [],
            "emojis": [],
            "reasons": [],
            "confidence": "low",
            "openai_usage": None,
            "fallback_used": True,
        }

# Exports
__all__ = ["ask_gpt_for_emojis", "get_openai_emojis_safe", "ALLOWED_EMOJI", "ALLOWED_IDS"]
