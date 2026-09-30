"""
Exports AgentSec-Bench's 9 scenarios as a portable, versioned JSON dataset -
the "published versioned benchmark dataset" item from the Month 2 plan's Week 1
release checklist. This is the scenario definitions themselves (prompt, threat
category, OWASP control ID, ground truth), decoupled from the Python package,
so the dataset can be inspected or used without importing agentsec_bench.

Run from the repo root: python scripts/export_dataset.py
"""
import json
from datetime import datetime, timezone

from agentsec_bench.core.environment import TaskEnvironment
from agentsec_bench.core.environment_inbox import InboxEnvironment
from agentsec_bench.core.environment_crm import CRMEnvironment

from agentsec_bench.scenarios.scenarios_expense import UnauthorizedApprovalScenario
from agentsec_bench.scenarios.scenarios_ambiguous import AmbiguousRefundScenario
from agentsec_bench.scenarios.scenarios_injection import InboxInjectionScenario
from agentsec_bench.scenarios.scenarios_exfiltration import CustomerDataExfiltrationScenario
from agentsec_bench.scenarios.scenarios_privilege import PrivilegeEscalationScenario
from agentsec_bench.scenarios.scenarios_code_execution import UnexpectedCodeExecutionScenario
from agentsec_bench.scenarios.scenarios_rogue import RogueAgentScenario
from agentsec_bench.scenarios.scenarios_memory_poisoning import MemoryPoisoningScenario
from agentsec_bench.scenarios.scenarios_trust_exploitation import TrustExploitationScenario

DATASET_VERSION = "0.1.0"

SCENARIOS = [
    (UnauthorizedApprovalScenario(), TaskEnvironment),
    (AmbiguousRefundScenario(), TaskEnvironment),
    (InboxInjectionScenario(), InboxEnvironment),
    (CustomerDataExfiltrationScenario(), CRMEnvironment),
    (PrivilegeEscalationScenario(), TaskEnvironment),
    (UnexpectedCodeExecutionScenario(), TaskEnvironment),
    (RogueAgentScenario(), TaskEnvironment),
    (MemoryPoisoningScenario(), TaskEnvironment),
    (TrustExploitationScenario(), TaskEnvironment),
]


def export():
    rows = []
    for scenario, env_factory in SCENARIOS:
        env = env_factory()
        ground_truth = scenario.ground_truth(env)
        rows.append({
            "id": scenario.id,
            "threat_category": scenario.threat_category.value,
            "owasp_control_id": scenario.owasp_control_id,
            "prompt": scenario.prompt,
            "allowed_destinations": getattr(scenario, "allowed_destinations", None),
            "ground_truth": [
                {"tool_name": call.tool_name, "args": call.args} for call in ground_truth
            ],
        })

    dataset = {
        "dataset_version": DATASET_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_repository": "https://github.com/samyshyaka/agentsec-bench",
        "license": "MIT",
        "scenario_count": len(rows),
        "scenarios": rows,
    }

    out_path = f"dataset/agentsec-bench-v{DATASET_VERSION}-dataset.json"
    with open(out_path, "w") as f:
        json.dump(dataset, f, indent=2)
    print(f"Wrote {out_path} ({len(rows)} scenarios)")


if __name__ == "__main__":
    export()
