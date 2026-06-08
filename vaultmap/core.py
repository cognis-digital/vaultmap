"""VAULTMAP core engine.

Real logic: PBKDF2-HMAC-SHA256 key derivation, a stream cipher built from
HMAC-SHA256 in counter mode (CTR), and HMAC authentication (encrypt-then-MAC).
All standard library only -- no external crypto deps, no network.

The vault file format (JSON):
{
  "magic": "VAULTMAP",
  "version": 1,
  "kdf": {"name": "pbkdf2_sha256", "iterations": N, "salt": b64},
  "nonce": b64,
  "ciphertext": b64,
  "mac": b64
}

The decrypted payload is a JSON document of entries (accounts/assets) plus
metadata. Designed to be handed to an executor: each entry can carry
instructions, location of credentials, and beneficiary notes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

MAGIC = "VAULTMAP"
FORMAT_VERSION = 1
DEFAULT_ITERATIONS = 200_000
KEY_LEN = 32  # 256-bit
NONCE_LEN = 16

# Categories useful for estate inventory; not enforced but validated/normalized.
CATEGORIES = (
    "bank",
    "investment",
    "retirement",
    "crypto",
    "real_estate",
    "insurance",
    "property",
    "digital",
    "liability",
    "other",
)


class VaultError(Exception):
    """Raised on any vault operation failure (bad password, tamper, etc.)."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256."""
    if not password:
        raise VaultError("password must not be empty")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, KEY_LEN)


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC-SHA256 counter-mode keystream."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt_blob(key: bytes, plaintext: bytes, nonce: Optional[bytes] = None) -> Dict[str, str]:
    """Encrypt-then-MAC. Returns dict with nonce, ciphertext, mac (all b64)."""
    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    ks = _keystream(key, nonce, len(plaintext))
    ct = bytes(p ^ k for p, k in zip(plaintext, ks))
    mac = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return {"nonce": _b64e(nonce), "ciphertext": _b64e(ct), "mac": _b64e(mac)}


def decrypt_blob(key: bytes, nonce_b64: str, ct_b64: str, mac_b64: str) -> bytes:
    """Verify MAC then decrypt. Raises VaultError on tamper/wrong key."""
    nonce = _b64d(nonce_b64)
    ct = _b64d(ct_b64)
    expected = _b64d(mac_b64)
    actual = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, actual):
        raise VaultError("authentication failed: wrong password or tampered vault")
    ks = _keystream(key, nonce, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks))


@dataclass
class Entry:
    """A single account/asset inventory record."""
    id: str
    name: str
    category: str = "other"
    institution: str = ""
    identifier: str = ""  # masked account/policy number, wallet label, etc.
    value: float = 0.0
    currency: str = "USD"
    beneficiary: str = ""
    location: str = ""  # where to find credentials/docs
    notes: str = ""
    updated: float = field(default_factory=lambda: time.time())

    def normalized(self) -> "Entry":
        cat = (self.category or "other").strip().lower()
        if cat not in CATEGORIES:
            cat = "other"
        self.category = cat
        return self


class Vault:
    """In-memory inventory with encrypted persistence."""

    def __init__(self, entries: Optional[List[Entry]] = None, iterations: int = DEFAULT_ITERATIONS):
        self.entries: List[Entry] = entries or []
        self.iterations = iterations

    # ---- entry management -------------------------------------------------
    def add(self, entry: Entry) -> Entry:
        entry.normalized()
        if any(e.id == entry.id for e in self.entries):
            raise VaultError(f"duplicate entry id: {entry.id}")
        self.entries.append(entry)
        return entry

    def remove(self, entry_id: str) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.id != entry_id]
        return len(self.entries) != before

    def get(self, entry_id: str) -> Optional[Entry]:
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    # ---- analytics --------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        """Estate-grade rollup: totals by category, net worth, gaps."""
        by_cat: Dict[str, Dict[str, Any]] = {}
        assets = 0.0
        liabilities = 0.0
        for e in self.entries:
            bucket = by_cat.setdefault(e.category, {"count": 0, "value": 0.0})
            bucket["count"] += 1
            bucket["value"] += e.value
            if e.category == "liability" or e.value < 0:
                liabilities += abs(e.value) if e.value < 0 else e.value
            else:
                assets += e.value
        # entries missing executor-critical info
        missing_beneficiary = [e.id for e in self.entries if not e.beneficiary.strip()]
        missing_location = [e.id for e in self.entries if not e.location.strip()]
        return {
            "entry_count": len(self.entries),
            "total_assets": round(assets, 2),
            "total_liabilities": round(liabilities, 2),
            "net_worth": round(assets - liabilities, 2),
            "by_category": {k: {"count": v["count"], "value": round(v["value"], 2)}
                            for k, v in sorted(by_cat.items())},
            "missing_beneficiary": missing_beneficiary,
            "missing_location": missing_location,
            "readiness_pct": self._readiness(),
        }

    def _readiness(self) -> float:
        """Estate-planning readiness: fraction of entries with full executor info."""
        if not self.entries:
            return 0.0
        complete = sum(
            1 for e in self.entries
            if e.beneficiary.strip() and e.location.strip() and e.institution.strip()
        )
        return round(100.0 * complete / len(self.entries), 1)

    # ---- serialization ----------------------------------------------------
    def to_payload(self) -> Dict[str, Any]:
        return {
            "magic": MAGIC,
            "generated": time.time(),
            "entries": [asdict(e) for e in self.entries],
        }

    @classmethod
    def from_payload(cls, payload: Dict[str, Any], iterations: int = DEFAULT_ITERATIONS) -> "Vault":
        if payload.get("magic") != MAGIC:
            raise VaultError("payload is not a VAULTMAP document")
        entries = [Entry(**ed).normalized() for ed in payload.get("entries", [])]
        return cls(entries=entries, iterations=iterations)

    # ---- encrypted file IO ------------------------------------------------
    def save(self, path: str, password: str) -> None:
        salt = os.urandom(16)
        key = derive_key(password, salt, self.iterations)
        plaintext = json.dumps(self.to_payload(), separators=(",", ":")).encode("utf-8")
        blob = encrypt_blob(key, plaintext)
        doc = {
            "magic": MAGIC,
            "version": FORMAT_VERSION,
            "kdf": {"name": "pbkdf2_sha256", "iterations": self.iterations, "salt": _b64e(salt)},
            "nonce": blob["nonce"],
            "ciphertext": blob["ciphertext"],
            "mac": blob["mac"],
        }
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str, password: str) -> "Vault":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except FileNotFoundError as exc:
            raise VaultError(f"vault file not found: {path}") from exc
        except (json.JSONDecodeError, OSError) as exc:
            raise VaultError(f"cannot read vault file: {exc}") from exc
        if doc.get("magic") != MAGIC or doc.get("version") != FORMAT_VERSION:
            raise VaultError("unrecognized or unsupported vault file")
        kdf = doc.get("kdf", {})
        iterations = int(kdf.get("iterations", DEFAULT_ITERATIONS))
        salt = _b64d(kdf["salt"])
        key = derive_key(password, salt, iterations)
        plaintext = decrypt_blob(key, doc["nonce"], doc["ciphertext"], doc["mac"])
        payload = json.loads(plaintext.decode("utf-8"))
        return cls.from_payload(payload, iterations=iterations)
