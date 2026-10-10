from typing import Dict, Any
from groq import Groq

from app.config import (
    GROQ_API_KEY,
    GROQ_PROMPT_GUARD_MODEL,
    PROMPT_GUARD_THRESHOLD,
)


class GroqPromptGuard:
    """
    Groq-hosted Meta Llama Prompt Guard 2.
    It is a binary prompt-attack classifier: BENIGN/MALICIOUS.
    """

    def __init__(self):
        if not GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY is not configured.")
        self.client = Groq(api_key=GROQ_API_KEY)

    def scan(self, text: str) -> Dict[str, Any]:
        # Prompt Guard 2 has a 512-token context limit. The application
        # performs chunking at the firewall level; this is a safety fallback.
        text = text[:6000]
        response = self.client.chat.completions.create(
            model=GROQ_PROMPT_GUARD_MODEL,
            messages=[{"role": "user", "content": text}],
            temperature=0,
            max_tokens=8,
        )
        raw = (response.choices[0].message.content or "").strip().upper()

        # Some deployments return LABEL_0/LABEL_1; others expose the
        # human-readable label.
        malicious = ("MALICIOUS" in raw) or ("LABEL_1" in raw)
        benign = ("BENIGN" in raw) or ("LABEL_0" in raw)

        return {
            "model": GROQ_PROMPT_GUARD_MODEL,
            "raw": raw,
            "malicious": malicious and not benign,
            "threshold": PROMPT_GUARD_THRESHOLD,
            "confidence": None,
            "note": "Prompt Guard 2 is used as a specialized prompt-attack gate.",
        }
