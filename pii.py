from __future__ import annotations

import hashlib
import hmac
import os
import re
import base64
from typing import Optional


_HASH_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")
_NON_DIGIT_RE = re.compile(r"\D+")

_V0_PREFIX = "v0:"
_V1_PREFIX = "v1:"
_V0_NONCE_LEN = 16
_V0_TAG_LEN = 32


def looks_like_sha256_hex(value: str) -> bool:
    return bool(_HASH_HEX_RE.fullmatch(str(value or "").strip()))


def get_pepper() -> str:
    return str(os.getenv("PEPPER", "") or "").strip()


def require_pepper() -> str:
    pepper = get_pepper()
    if not pepper:
        raise RuntimeError("Missing env var PEPPER (required for deterministic PII hashing)")
    return pepper


def get_pii_enc_key() -> str:
    """
    Symmetric encryption key for storing full PII encrypted-at-rest.

    This is optional; when unset, we fall back to PEPPER so full PII can still be
    stored encrypted-at-rest without introducing another secret.
    """

    return str(os.getenv("PII_ENC_KEY", "") or "").strip() or get_pepper()


def _derive_aes256_key(key_material: str) -> bytes:
    """
    Returns a 32-byte key for AES-256-GCM.

    Accepts:
    - base64-encoded 32 bytes
    - 64-char hex
    - any string (derived via SHA-256; use a strong random secret in prod)
    """

    s = str(key_material or "").strip()
    if not s:
        return b""

    # Base64 (preferred)
    try:
        raw = base64.b64decode(s, validate=True)
        if len(raw) == 32:
            return raw
    except Exception:
        pass

    # Hex
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        try:
            return bytes.fromhex(s)
        except Exception:
            return b""

    # Passphrase fallback (still deterministic; prefer base64/hex in prod)
    return hashlib.sha256(s.encode("utf-8")).digest()


def _try_get_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

        return AESGCM
    except Exception:
        return None


def _v0_keystream(key: bytes, nonce: bytes, aad: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        ctr = counter.to_bytes(4, "big", signed=False)
        block = hmac.new(key, b"pii:v0:stream:" + nonce + ctr + aad, hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:nbytes])


def _v0_encrypt(plaintext: bytes, *, key: bytes, aad: bytes) -> str:
    nonce = os.urandom(_V0_NONCE_LEN)
    ks = _v0_keystream(key, nonce, aad, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(key, b"pii:v0:tag:" + nonce + ct + aad, hashlib.sha256).digest()
    blob = nonce + ct + tag
    return _V0_PREFIX + base64.urlsafe_b64encode(blob).decode("ascii")


def _v0_decrypt(blob: bytes, *, key: bytes, aad: bytes) -> bytes | None:
    if len(blob) < _V0_NONCE_LEN + _V0_TAG_LEN:
        return None
    nonce = blob[:_V0_NONCE_LEN]
    tag = blob[-_V0_TAG_LEN:]
    ct = blob[_V0_NONCE_LEN:-_V0_TAG_LEN]
    expected = hmac.new(key, b"pii:v0:tag:" + nonce + ct + aad, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        return None
    ks = _v0_keystream(key, nonce, aad, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def encrypt_pii(plaintext: str, *, key: str, aad: str = "") -> str:
    """
    Encrypts plaintext into a stable versioned string suitable for DB storage.

    Uses AES-256-GCM with a random 12-byte nonce and optional AAD.
    Returns "" if key is missing or encryption isn't available.
    """

    pt = str(plaintext or "").strip()
    if not pt:
        return ""

    key_bytes = _derive_aes256_key(key)
    if not key_bytes:
        return ""

    aad_bytes = str(aad or "").encode("utf-8") if aad else b""

    AESGCM = _try_get_aesgcm()
    if AESGCM is not None:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key_bytes)
        ct = aesgcm.encrypt(nonce, pt.encode("utf-8"), aad_bytes if aad else None)
        blob = nonce + ct
        return _V1_PREFIX + base64.urlsafe_b64encode(blob).decode("ascii")

    # Fallback when `cryptography` isn't available (keeps DB free of plaintext).
    return _v0_encrypt(pt.encode("utf-8"), key=key_bytes, aad=aad_bytes)


def decrypt_pii(ciphertext: str, *, key: str, aad: str = "") -> str:
    """
    Decrypts a value encrypted by encrypt_pii(). Returns "" on failure.
    """

    s = str(ciphertext or "").strip()
    if not s:
        return ""

    version = "v1"
    if s.startswith(_V1_PREFIX):
        s = s[len(_V1_PREFIX) :]
        version = "v1"
    elif s.startswith(_V0_PREFIX):
        s = s[len(_V0_PREFIX) :]
        version = "v0"

    key_bytes = _derive_aes256_key(key)
    if not key_bytes:
        return ""

    aad_bytes = str(aad or "").encode("utf-8") if aad else b""

    try:
        blob = base64.urlsafe_b64decode(s.encode("ascii"))
    except Exception:
        return ""

    if version == "v0":
        pt0 = _v0_decrypt(blob, key=key_bytes, aad=aad_bytes)
        if not pt0:
            return ""
        try:
            return pt0.decode("utf-8")
        except Exception:
            return ""

    AESGCM = _try_get_aesgcm()
    if AESGCM is None:
        return ""

    if len(blob) < 12 + 16:
        return ""

    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key_bytes)
    try:
        pt = aesgcm.decrypt(nonce, ct, aad_bytes if aad else None)
    except Exception:
        return ""
    try:
        return pt.decode("utf-8")
    except Exception:
        return ""


def hmac_sha256_hex(pepper: str, normalized_value: str) -> str:
    p = str(pepper or "")
    v = str(normalized_value or "")
    if not p or not v:
        return ""
    return hmac.new(p.encode("utf-8"), v.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def normalize_name(name: str) -> str:
    s = str(name or "").strip().lower()
    if not s:
        return ""
    s = _WS_RE.sub(" ", s).strip()
    return s


def normalize_phone(phone: str) -> str:
    digits = _NON_DIGIT_RE.sub("", str(phone or ""))
    if not digits:
        return ""

    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    if digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]
    if len(digits) > 10:
        digits = digits[-10:]

    if len(digits) < 8:
        return ""
    return digits


def mask_email(email: str) -> str:
    s = normalize_email(email)
    if not s or "@" not in s:
        return ""
    local, domain = s.split("@", 1)
    if not local or not domain:
        return ""

    local_keep = local[:2] if len(local) >= 2 else local[:1]
    domain_keep = domain[:1] if domain else ""

    parts = domain.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        root = parts[0]
        domain_masked = f"{domain_keep}***.{tld}" if tld else f"{domain_keep}***"
        if not root:
            domain_masked = f"{domain_keep}***"
    else:
        domain_masked = f"{domain_keep}***"

    return f"{local_keep}***@{domain_masked}"


def mask_phone(phone: str) -> str:
    digits = normalize_phone(phone)
    if not digits:
        return ""
    last4 = digits[-4:] if len(digits) >= 4 else digits
    return f"91xxxxxx{last4}"


def mask_name(name: str) -> str:
    s = normalize_name(name)
    if not s:
        return ""
    keep = s[:2] if len(s) >= 2 else s[:1]
    return f"{keep}***"


def hash_email(email: str, pepper: str) -> str:
    return hmac_sha256_hex(pepper, normalize_email(email))


def hash_name(name: str, pepper: str) -> str:
    return hmac_sha256_hex(pepper, normalize_name(name))


def hash_phone(phone: str, pepper: str) -> str:
    return hmac_sha256_hex(pepper, normalize_phone(phone))


def maybe_hash_from_stored(value: str, *, kind: str, pepper: str) -> tuple[str, str]:
    """
    Returns (hash, masked) for a value that may already be hashed.

    If the value looks like a sha256 hex digest, treat it as the hash and return masked="".
    Otherwise, compute both hash+masked from the raw value.
    """
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if looks_like_sha256_hex(raw):
        return raw.lower(), ""

    if kind == "email":
        return hash_email(raw, pepper), mask_email(raw)
    if kind == "phone":
        return hash_phone(raw, pepper), mask_phone(raw)
    if kind == "name":
        return hash_name(raw, pepper), mask_name(raw)
    return "", ""
