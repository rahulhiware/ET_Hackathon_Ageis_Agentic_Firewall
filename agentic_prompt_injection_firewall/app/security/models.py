from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "Instruction Override"
    ROLE_CHANGE = "Role Change"
    SECRET_EXTRACTION = "Secret Extraction"
    TOOL_ABUSE = "Tool Abuse"
    CREDENTIAL_THEFT = "Credential Theft"
    CONTEXT_POISONING = "Context Poisoning"
    MULTI_STEP_JAILBREAK = "Multi-Step Jailbreak"
    ENCODED_INSTRUCTIONS = "Encoded Instructions"
    INDIRECT_PROMPT_INJECTION = "Indirect Prompt Injection"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class Threat(BaseModel):
    attack_type: AttackType
    confidence: float = Field(ge=0, le=1)
    evidence: List[str] = Field(default_factory=list)
    source: str = "rule"


class ScanResult(BaseModel):
    decision: Decision
    risk_score: float = Field(ge=0, le=1)
    is_injection: bool
    threats: List[Threat] = Field(default_factory=list)
    normalized_content: str
    safe_content: str
    provenance: Dict[str, Any] = Field(default_factory=dict)
    prompt_guard: Dict[str, Any] = Field(default_factory=dict)
    semantic_analysis: Dict[str, Any] = Field(default_factory=dict)
    encoded_payloads: List[str] = Field(default_factory=list)
    explanation: List[str] = Field(default_factory=list)
