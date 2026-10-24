# Agenomics 0.9.7 | Author: Dm.Andreyanov | Brand: Prizolov Lab | © 2026
"""
sanitize.py. Очистка текста ошибок перед записью в базу доказательств.

Тексты ошибок провайдеров (лимиты, авторизация) могут содержать
идентификаторы организации и фрагменты ключей. База выкладывается как
публичный артефакт, поэтому такие значения заменяются метками до записи.
Структура ошибки (класс, статус, повтор) при этом сохраняется.

Проект: Prizolov Lab
"""

import re
from typing import Optional

_PATTERNS = [
    (re.compile(r"\borg_[A-Za-z0-9]{6,}"), "[org-id]"),
    (re.compile(r"\b(?:gsk|sk|hf|ghp|gho|github_pat|xox[abpr])[-_][A-Za-z0-9_\-]{10,}"), "[api-key]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}"), "[api-key]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}"), "Bearer [token]"),
    (re.compile(r"(?i)\b(api[_-]?key|token|secret|password)(\s*[=:]\s*)[^\s,;'\"]{6,}"), r"\1\2[redacted]"),
]


def redact(text: Optional[str]) -> Optional[str]:
    """Заменяет идентификаторы организации, ключи и токены метками."""
    if not text:
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
