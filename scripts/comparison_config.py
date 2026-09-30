"""
Defines the baseline comparison between AgentSec-Bench and AgentDojo.

This is scaffolding: it specifies which models and which scenario pairs
will be compared once live model access is available. It does not yet
execute anything against AgentDojo directly, since that lives in a
separate repository (agentdojo clone) with its own environment.
"""

# Models to run both frameworks against, for a controlled comparison.
# Using the same models in both frameworks is what makes the comparison valid.
COMPARISON_MODELS = [
    "gpt-4o-mini-2024-07-18",
    "claude-3-haiku-20240307",
]

# Maps an AgentSec-Bench scenario to the closest comparable AgentDojo
# suite/task, where one genuinely exists. Not every AgentSec-Bench
# scenario has an AgentDojo equivalent — those are marked None, since
# AgentSec-Bench's threat categories intentionally extend beyond what
# AgentDojo covers (this is itself part of the gap-analysis finding).
SCENARIO_TO_AGENTDOJO_MAPPING = {
    "PI-001": {
        "agentdojo_suite": "workspace",
        "agentdojo_task": "user_task_0",
        "note": "Closest AgentDojo equivalent: workspace suite, prompt injection via email content.",
    },
    "UTI-001": {
        "agentdojo_suite": None,
        "agentdojo_task": None,
        "note": "No direct AgentDojo equivalent. AgentDojo does not model role-based tool "
                "authorization; this scenario tests a threat category outside its scope.",
    },
    "UTI-002": {
        "agentdojo_suite": None,
        "agentdojo_task": None,
        "note": "No direct AgentDojo equivalent. Same reason as UTI-001.",
    },
    "EX-001": {
        "agentdojo_suite": "workspace",
        "agentdojo_task": None,  # closest is InjectionTask4 (Facebook code exfiltration), needs manual mapping
        "note": "Conceptually similar to AgentDojo's InjectionTask4 (data exfiltration via email). "
                "Not a direct 1:1 task match, since environments differ.",
    },
    "PE-001": {
        "agentdojo_suite": None,
        "agentdojo_task": None,
        "note": "No direct AgentDojo equivalent. Privilege escalation via role/permission is "
                "outside AgentDojo's current scope.",
    },

        "CE-001": {
        "agentdojo_suite": None,
        "agentdojo_task": None,
        "note": "No direct AgentDojo equivalent. Unexpected/unsafe code execution via a "
                "compromised or over-trusted devops tool is outside AgentDojo's current scope.",
    },
    "RA-001": {
        "agentdojo_suite": None,
        "agentdojo_task": None,
        "note": "No direct AgentDojo equivalent. Rogue/overzealous autonomous cleanup behavior "
                "is a threat category AgentDojo does not model.",
    },
    "MP-001": {
        "agentdojo_suite": None,
        "agentdojo_task": None,
        "note": "No direct AgentDojo equivalent. Memory/context poisoning across a multi-step "
                "interaction is outside AgentDojo's current task model.",
    },
    "HT-001": {
        "agentdojo_suite": None,
        "agentdojo_task": None,
        "note": "No direct AgentDojo equivalent. Human-agent trust exploitation (social "
                "engineering directed at the agent operator) is outside AgentDojo's scope.",
    },
}