import re
from typing import Union

from agno.exceptions import InputCheckError
from agno.guardrails.base import BaseGuardrail
from agno.run.agent import RunInput
from agno.run.team import TeamRunInput


class CredentialLeakGuardrail(BaseGuardrail):
    """
    Additional Agno-native pre-hook.
    It is intentionally narrow: it blocks obvious credential exfiltration
    requests that mention secrets/tokens/keys together with reveal/show/send.
    """

    PATTERNS = [
        r"(reveal|show|print|dump|send|export).{0,80}(api key|access token|password|private key|secret key|credentials)",
        r"(give|provide).{0,50}(system prompt|developer prompt|hidden instructions)",
    ]

    def check(self, run_input: Union[RunInput, TeamRunInput]) -> None:
        content = run_input.input_content_string()
        for pattern in self.PATTERNS:
            if re.search(pattern, content, flags=re.I | re.S):
                raise InputCheckError(
                    "Credential/secret extraction attempt blocked by Aegis custom guardrail."
                )

    async def async_check(self, run_input):
        self.check(run_input)
