"""
Emoji tagger (emoji_id output)

This module analyzes source code (Python or other) using AST (with regex fallback)
and returns an emoji tagging result that includes:
 - emoji_ids: list of TossFace emoji IDs (primary)
 - emojis: list of unicode emoji fallbacks
 - emoji_labels: list of label strings (categories)
 - tags: same as labels (for backwards compatibility)
 - scores: score map by label (float)

Replace the EMOJI_MAP first entry (emoji_id) with real TossFace IDs or asset URLs
when they are available.
"""
import ast
import re
from collections import Counter, defaultdict
from typing import Dict, List

# EMOJI_MAP:
# label -> (toss_id, unicode_fallback, [keywords/libs...])
# NOTE: Replace toss_* ids with your actual TossFace emoji IDs or asset URLs as needed.
EMOJI_MAP = {
    # AI / ML
    "ai":         ("toss_ai_01",        "🤖", ["torch", "tensorflow", "keras", "pytorch", "transformers", "onnx", "xgboost", "lightgbm"]),
    "ml_research":("toss_brain_01",     "🧠", ["model", "train", "fit", "loss", "optimizer", "inference", "eval"]),
    # testing / validation
    "tests":      ("toss_lab_01",       "🧪", ["pytest", "unittest", "assert", "tox", "mock"]),
    # analytics / data
    "analytics":  ("toss_data_01",      "📊", ["pandas", "numpy", "dataframe", "groupby", "aggregate", "analytics", "read_csv"]),
    "performance":("toss_perf_01",      "📈", ["benchmark", "profile", "timeit", "latency", "throughput", "perf"]),
    # web / api
    "web":        ("toss_web_01",       "🌐", ["fastapi", "flask", "django", "starlette", "request", "response", "endpoint", "httpx", "requests", "aiohttp"]),
    # data storage / db
    "db":         ("toss_db_01",        "🛢️", ["sqlalchemy", "pymongo", "psycopg2", "pymysql", "redis", "sqlite3", "mongodb", "query"]),
    # system / os
    "sys":        ("toss_sys_01",       "🛠️", ["os", "sys", "shutil", "pathlib", "subprocess", "multiprocessing"]),
    # networking
    "network":    ("toss_net_01",       "🔗", ["socket", "grpc", "websocket", "http.client", "requests", "aiohttp"]),
    # security / crypto
    "security":   ("toss_sec_01",       "🔒", ["hashlib", "hmac", "cryptography", "jwt", "secrets", "encrypt", "decrypt", "token"]),
    # infra / container
    "infra":      ("toss_infra_01",     "🐳", ["docker", "dockerfile", "compose", "kubernetes", "kubectl", "helm", "container"]),
    # mlops / pipeline
    "mlops":      ("toss_mlops_01",     "⚙️", ["mlflow", "sagemaker", "airflow", "kubeflow", "dag", "pipeline"]),
    # devtools / CLI
    "devtools":   ("toss_dev_01",       "🧰", ["cli", "click", "argparse", "setup.py", "makefile"]),
    # packaging / artifacts
    "packaging":  ("toss_pack_01",      "📦", ["wheel", "pip", "setuptools", "poetry", "artifact"]),
    # deployment / release
    "deploy":     ("toss_deploy_01",    "🚀", ["deploy", "release", "k8s", "helm", "rolling"]),
    # mobile / client
    "mobile":     ("toss_mobile_01",    "📱", ["android", "ios", "kotlin", "swift", "react-native", "flutter"]),
    # game / interactive
    "game":       ("toss_game_01",      "🎮", ["pygame", "unity", "godot", "render", "frame", "fps"]),
    # image / vision
    "image":      ("toss_image_01",     "🖼️", ["opencv", "PIL", "pillow", "cv2", "image", "jpeg", "png"]),
    # audio / speech
    "audio":      ("toss_audio_01",     "🎧", ["librosa", "soundfile", "pyaudio", "wave", "wav", "mp3"]),
    # video / streaming
    "video":      ("toss_video_01",     "🎬", ["ffmpeg", "cv2.videocapture", "stream", "hls", "rtmp"]),
    # debug / analysis
    "analysis":   ("toss_debug_01",     "🔍", ["debug", "trace", "inspect", "pdb", "logging", "traceback"]),
    # plugin / extension
    "plugin":     ("toss_plugin_01",    "🧩", ["plugin", "extension", "hook", "register"]),
    # scheduler / cron jobs
    "scheduler":  ("toss_sched_01",     "🔁", ["cron", "schedule", "apscheduler", "celery", "beat"]),
    # documentation
    "docs":       ("toss_docs_01",      "📚", ["docs", "readme", "sphinx", "mkdocs", "swagger", "openapi"]),
    # logging / audit
    "logging":    ("toss_log_01",       "🧾", ["logging", "audit", "access_log", "auditlog"]),
    # routing / API design
    "routing":    ("toss_route_01",     "🧭", ["route", "router", "endpoint", "path", "url"]),
    # blockchain / crypto-ledger
    "blockchain": ("toss_chain_01",     "🪙", ["web3", "ethers", "solidity", "contract", "smartcontract", "blockchain"]),
    # telemetry / iot
    "telemetry":  ("toss_tele_01",      "📡", ["mqtt", "edge", "iot", "sensor", "telemetry"]),
    # warning / dangerous / suspicious
    "warning":    ("toss_warn_01",      "⚠️", ["eval", "exec", "__import__", "os.system", "rm -rf", "fork", "ctypes"]),
    # scripting / python script fallback
    "script":     ("toss_snake_01",     "🐍", ["python", ".py", "shebang", "def", "import"]),
}

# Optional keyword-to-label boosting map
KEYWORD_MAP = {
    "model": "ai", "train": "ai", "inference": "ai", "predict": "ai",
    "dataframe": "analytics", "csv": "analytics", "read_csv": "analytics",
    "request": "web", "response": "web", "endpoint": "web",
    "query": "db", "cursor": "db",
    "socket": "network", "listen": "network",
    "encrypt": "security", "decrypt": "security", "token": "security",
    "docker": "infra", "container": "infra",
    "cron": "scheduler", "celery": "scheduler",
    "pytest": "tests", "unittest": "tests",
}

COMMON_IGNORE = {"self", "__init__", "__name__", "__main__"}


def _ast_extract(code: str):
    """Extract imports, call names, attr names, and other identifiers via AST."""
    imports = set()
    call_names = []
    attr_names = []
    names = []
    try:
        tree = ast.parse(code)
    except Exception:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                call_names.append(func.id)
            elif isinstance(func, ast.Attribute):
                attr_names.append(func.attr)
                try:
                    if isinstance(func.value, ast.Name):
                        call_names.append(func.value.id)
                except Exception:
                    pass
        elif isinstance(node, ast.Attribute):
            attr_names.append(node.attr)
        elif isinstance(node, ast.Name):
            if node.id not in COMMON_IGNORE:
                names.append(node.id)
    return {
        "imports": set(i.lower() for i in imports if isinstance(i, str)),
        "call_names": [c.lower() for c in call_names if isinstance(c, str)],
        "attr_names": [a.lower() for a in attr_names if isinstance(a, str)],
        "names": [n.lower() for n in names if isinstance(n, str)],
    }


def _regex_extract(code: str):
    """Fallback extraction using regex tokens."""
    imports = set(re.findall(r"^\s*(?:from|import)\s+([a-zA-Z0-9_\.]+)", code, flags=re.MULTILINE))
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{1,30}", code)
    return {
        "imports": set(i.lower().split(".")[0] for i in imports),
        "call_names": [t.lower() for t in tokens],
        "attr_names": [t.lower() for t in tokens],
        "names": [t.lower() for t in tokens],
    }


def map_emojis(code: str, top_n: int = 3) -> Dict[str, List[str]]:
    """
    Analyze code and return a dict with keys:
      - emoji_ids: list[str]  (primary, TossFace IDs or asset IDs)
      - emojis: list[str]     (unicode fallbacks)
      - emoji_labels: list[str]
      - tags: list[str]
      - scores: dict[label->float]
    """
    info = _ast_extract(code)
    if info is None:
        info = _regex_extract(code)

    # scoring
    scores = defaultdict(float)
    counts = Counter()

    # weight imports more
    for imp in info["imports"]:
        counts[imp] += 2
    for n in info["call_names"]:
        counts[n] += 1.5
    for n in info["attr_names"]:
        counts[n] += 1.0
    for n in info["names"]:
        counts[n] += 0.5

    # map tokens to categories
    for token, cnt in counts.items():
        for label, (toss_id, uni, libs) in EMOJI_MAP.items():
            for lib in libs:
                if lib in token:
                    scores[label] += cnt
        # keyword boosting
        if token in KEYWORD_MAP:
            scores[KEYWORD_MAP[token]] += cnt * 0.8

    # small heuristics
    lower = code.lower()
    if "import pandas" in lower or "read_csv" in lower:
        if "analytics" in EMOJI_MAP:
            scores["analytics"] += 2
    if "def main" in lower and "argparse" in lower and "devtools" in EMOJI_MAP:
        scores["devtools"] += 0.5

    # fallback
    if not scores:
        fallback = EMOJI_MAP.get("script", ("toss_snake_01", "🐍", []))
        return {
            "emoji_ids": [fallback[0]],
            "emojis": [fallback[1]],
            "emoji_labels": ["script"],
            "tags": ["script"],
            "scores": {}
        }

    # choose top_n labels
    ordered = sorted(scores.items(), key=lambda x: (-x[1], x[0]))
    chosen = [label for label, _ in ordered[:top_n] if _ > 0]

    emoji_ids = []
    emojis = []
    labels = []
    tags = []
    for label in chosen:
        toss_id, uni, _ = EMOJI_MAP.get(label, (None, None, []))
        if toss_id:
            emoji_ids.append(toss_id)
        if uni:
            emojis.append(uni)
        labels.append(label)
        tags.append(label)

    # dedupe and cap
    emoji_ids = list(dict.fromkeys(emoji_ids))[:top_n] or []
    emojis = list(dict.fromkeys(emojis))[:top_n] or []

    score_snapshot = {k: float(v) for k, v in scores.items()}

    return {
        "emoji_ids": emoji_ids,
        "emojis": emojis,
        "emoji_labels": labels,
        "tags": tags,
        "scores": score_snapshot
    }
