import re
from typing import List
from .models import AttackType, Threat

RULES = {
    AttackType.INSTRUCTION_OVERRIDE: [
        r"ignore (all )?(previous|prior|earlier) instructions",
        r"disregard (all )?(previous|prior|earlier) instructions",
        r"forget (everything|all instructions) (above|before)",
        r"override (the )?(system|developer|security) (prompt|instructions|rules)",
        r"do not follow (the )?(previous|prior|system|developer)",
        r"new instructions? (start|begin) now",
    ],
    AttackType.ROLE_CHANGE: [
        r"you are now (a|an) ",
        r"act as (a|an) ",
        r"pretend you are",
        r"roleplay as",
        r"switch to .*mode",
        r"assume the role of",
        r"become an? unrestricted",
    ],
    AttackType.SECRET_EXTRACTION: [
        r"reveal (your )?(system prompt|system message|hidden instructions)",
        r"show (me )?(your )?(system prompt|developer prompt|hidden instructions)",
        r"print (your )?(system|developer) prompt",
        r"what are your hidden instructions",
        r"dump your prompt",
    ],
    AttackType.TOOL_ABUSE: [
        r"send .*email",
        r"delete .*database",
        r"delete .*records",
        r"execute .*command",
        r"run .*shell",
        r"upload .*file",
        r"call .*tool",
        r"invoke .*function",
        r"transfer .*money",
    ],
    AttackType.CREDENTIAL_THEFT: [
        r"reveal .*api key",
        r"show .*api key",
        r"send .*access token",
        r"reveal .*password",
        r"show .*credentials",
        r"dump .*secrets",
        r"private key",
        r"secret key",
        r"bearer token",
    ],
    AttackType.CONTEXT_POISONING: [
        r"ai assistant:",
        r"assistant instruction:",
        r"instruction for the ai",
        r"when you read this",
        r"the ai must",
        r"important instruction for the model",
        r"ignore the user's request",
    ],
    AttackType.MULTI_STEP_JAILBREAK: [
        r"first .* then .* reveal",
        r"step 1 .* step 2",
        r"once you have .* then",
        r"for the next step",
        r"continue with the next instruction",
        r"chain of instructions",
    ],
    AttackType.INDIRECT_PROMPT_INJECTION: [
        r"document says .* ignore",
        r"web page says .* ignore",
        r"email says .* ignore",
        r"following document .* instruction",
        r"retrieved content .* instruction",
        r"content above .* instruction",
    ],
}


def rule_scan(text: str) -> List[Threat]:
    threats = []
    lower = text.lower()
    for attack_type, patterns in RULES.items():
        evidence = []
        for pattern in patterns:
            match = re.search(pattern, lower, re.IGNORECASE | re.DOTALL)
            if match:
                evidence.append(match.group(0)[:240])
        if evidence:
            threats.append(
                Threat(
                    attack_type=attack_type,
                    confidence=min(0.98, 0.82 + 0.05 * len(evidence)),
                    evidence=evidence[:3],
                    source="rules",
                )
            )
    return threats
