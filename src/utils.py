"""Utility functions for the CodeBadger Server."""

from pathlib import Path
from typing import List


def detect_project_language(project_path: Path) -> List[str]:
    """Detect programming languages in a project"""
    languages = []

    language_patterns = {
        "c": ["*.c", "*.h"],
        "cpp": ["*.cpp", "*.cxx", "*.cc", "*.hpp", "*.hxx"],
        "java": ["*.java", "pom.xml", "build.gradle"],
        "javascript": ["*.js", "package.json"],
        "typescript": ["*.ts", "*.tsx", "tsconfig.json"],
        "python": ["*.py", "requirements.txt", "setup.py", "pyproject.toml"],
        "go": ["*.go", "go.mod"],
        "kotlin": ["*.kt", "*.kts"],
        "scala": ["*.scala", "build.sbt"],
        "csharp": ["*.cs", "*.csproj", "*.sln"],
    }

    for lang, patterns in language_patterns.items():
        for pattern in patterns:
            if list(project_path.rglob(pattern)):
                if lang not in languages:
                    languages.append(lang)
                break

    return languages or ["unknown"]


def calculate_loc(project_path: Path, languages: List[str]) -> int:
    """Calculate lines of code in project"""
    extensions = {
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cxx", ".cc", ".hpp", ".hxx"],
        "java": [".java"],
        "javascript": [".js"],
        "typescript": [".ts", ".tsx"],
        "python": [".py"],
        "go": [".go"],
        "kotlin": [".kt", ".kts"],
        "scala": [".scala"],
        "csharp": [".cs"],
    }

    relevant_extensions = set()
    for lang in languages:
        if lang in extensions:
            relevant_extensions.update(extensions[lang])

    total_lines = 0
    for ext in relevant_extensions:
        for file_path in project_path.rglob(f"*{ext}"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    total_lines += sum(1 for line in f if line.strip())
            except Exception:
                continue

    return total_lines
