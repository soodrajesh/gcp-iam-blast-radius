from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import ValidationError

from .models import Snapshot

MAX_BINDINGS = 20000


class SnapshotError(ValueError):
    pass


def load(doc: Any) -> Snapshot:
    try:
        snap = Snapshot.model_validate(doc)
    except ValidationError as e:
        raise SnapshotError(f"invalid snapshot: {str(e)[:300]}") from e
    if len(snap.bindings) > MAX_BINDINGS:
        raise SnapshotError(f"snapshot has more than {MAX_BINDINGS} bindings")
    return snap


def sha256(snap: Snapshot) -> str:
    return hashlib.sha256(
        json.dumps(snap.model_dump(mode="json"), sort_keys=True).encode()
    ).hexdigest()
