def decision_logic(score: int):
    if score >= 70: return "block", False
    if score >= 40: return "sandbox", False
    return "allow", True

def suggest_limits(score: int, lang: str):
    t = min(max(score / 100, 0), 1)
    if lang == "python":
        return {
            "cpu_time_sec": int(1 + (10 - 1) * (1 - t)),
            "memory_mb": int(64 + (512 - 64) * (1 - t)),
            "wall_time_sec": int(2 + (20 - 2) * (1 - t)),
            "stdout_kb": int(16 + (256 - 16) * (1 - t)),
        }
    return {"cpu_time_sec": 2, "memory_mb": 128, "wall_time_sec": 5, "stdout_kb": 64}
