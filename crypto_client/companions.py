"""Companion file naming (spec sections 5 and 6): report.txt -> report.txt.enc etc."""


def companion_path(base_path: str, suffix: str) -> str:
    return f"{base_path}.{suffix}"
