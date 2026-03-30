from __future__ import annotations

import hashlib


def hash_client_binding(pop_key: str, client_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(pop_key.encode("utf-8"))
    digest.update(b"|")
    digest.update(client_id.encode("utf-8"))
    return digest.hexdigest()
