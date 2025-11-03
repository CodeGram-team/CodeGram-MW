import tokenize, io, ast

def comment_ratio(code: str) -> float:
    try:
        reader = io.BytesIO(code.encode("utf-8")).readline
        total = comments = 0
        for tok in tokenize.tokenize(reader):
            if tok.type == tokenize.COMMENT:
                comments += 1
            if tok.type not in (tokenize.ENCODING, tokenize.NL):
                total += 1
        return comments / total if total else 0.0
    except Exception:
        return 0.0

def avg_function_len_python(tree: ast.AST) -> float:
    if not tree: return 0.0
    lens = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and getattr(node, "body", None):
            start = getattr(node, "lineno", 0)
            end = max(getattr(n, "lineno", start) or start for n in ast.walk(node))
            if start and end >= start:
                lens.append(end - start + 1)
    return sum(lens) / len(lens) if lens else 0.0
