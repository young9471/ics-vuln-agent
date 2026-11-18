#!/usr/bin/env python3
"""Shared SHA256 cache for expensive static analyzers (Ghidra / ILSpyCmd).

Cache keys include the analyzer name/version and the file content hash, so an
edited binary or a different analyzer build never reuses stale output. The cache
is local-only and best-effort: a cache failure never fails the analysis.
"""
import hashlib
import json
import os
import tempfile
from pathlib import Path


def cache_root():
    env = os.environ.get("PROTOCOL_AGENT_ANALYZER_CACHE", "").strip()
    if env:
        return Path(env)
    return Path.home() / ".cache" / "protocol-agent" / "analyzers"


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cache_key(path, analyzer, version="1"):
    try:
        digest = file_sha256(path)
    except OSError:
        return ""
    return f"{analyzer}-{version}-{digest}.json"


def load(path, analyzer, version="1"):
    key = cache_key(path, analyzer, version)
    if not key:
        return None
    try:
        with open(cache_root() / key, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def store(path, analyzer, version, payload):
    key = cache_key(path, analyzer, version)
    if not key:
        return False
    root = cache_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=key + ".", dir=str(root))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, root / key)
        return True
    except OSError:
        return False