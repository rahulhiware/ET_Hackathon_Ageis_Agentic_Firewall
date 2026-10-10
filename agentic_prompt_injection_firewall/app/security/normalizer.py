import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote

ZERO_WIDTH = re.compile(r"[\\u200B-\\u200D\\u2060\\uFEFF]")
CONTROL_CHARS = re.compile(r"[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]")


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = ZERO_WIDTH.sub("", text)
    text = CONTROL_CHARS.sub(" ", text)
    text = html.unescape(text)
    return text


def decode_variants(text: str):
    variants = []
    url_decoded = unquote(text)
    if url_decoded != text:
        variants.append(("URL-decoded", url_decoded))

    compact = re.sub(r"\\s+", "", text)
    if len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            decoded = base64.b64decode(compact, validate=True).decode("utf-8")
            if decoded.strip():
                variants.append(("Base64-decoded", decoded))
        except Exception:
            pass

    compact_hex = re.sub(r"\\s+", "", text)
    if len(compact_hex) >= 16 and len(compact_hex) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact_hex):
        try:
            decoded = bytes.fromhex(compact_hex).decode("utf-8")
            if decoded.strip():
                variants.append(("Hex-decoded", decoded))
        except Exception:
            pass

    return variants


def normalize_and_decode(text: str):
    normalized = normalize_text(text)
    variants = decode_variants(normalized)
    return normalized, variants
