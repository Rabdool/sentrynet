"""Password hashing for dashboard administrators.

Uses bcrypt, as specified for ``user.password_hash`` in Chapter Four
(Table 4.1). Plain-text passwords are never stored.
"""
from __future__ import annotations

import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        # Malformed stored hash: treat as a failed login rather than crashing.
        return False
