import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_AGENT_MODEL = os.getenv("GROQ_AGENT_MODEL", "openai/gpt-oss-120b")
GROQ_PROMPT_GUARD_MODEL = os.getenv(
    "GROQ_PROMPT_GUARD_MODEL",
    "meta-llama/llama-prompt-guard-2-86m",
)
GROQ_SECURITY_CLASSIFIER_MODEL = os.getenv(
    "GROQ_SECURITY_CLASSIFIER_MODEL",
    "openai/gpt-oss-20b",
)
PROMPT_GUARD_THRESHOLD = float(os.getenv("PROMPT_GUARD_THRESHOLD", "0.80"))

MAX_TEXT_CHARS = 50000
MAX_SCAN_CHARS = 12000
