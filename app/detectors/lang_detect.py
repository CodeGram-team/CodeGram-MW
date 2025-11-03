LANG_HINTS = {
    "python": ["def ", "import ", "lambda ", "async def", "print("],
    "javascript": ["function ", "=>", "console.log", "export ", "import "],
    "java": ["public class", "System.out.println"],
    "cpp": ["#include", "std::", "int main("],
    "go": ["package main", "func main("],
    "rust": ["fn main(", "println!("],
    "kotlin": ["fun main(", "val ", "var "],
}

def detect_language(code: str, hint: str = "auto") -> str:
    if hint and hint != "auto":
        return hint.lower()
    sample = code[:2000]
    for lang, needles in LANG_HINTS.items():
        if any(n in sample for n in needles):
            return lang
    return "python"
