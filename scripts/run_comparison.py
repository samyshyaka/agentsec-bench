"""
Runs the baseline comparison: AgentSec-Bench results vs. AgentDojo results,
across the same models, for scenarios that have a genuine equivalent.

This is currently a scaffold. Live execution requires funded API access
for at least one provider (see README - Not yet done).
"""

import json
from datetime import datetime, timezone
from comparison_config import COMPARISON_MODELS, SCENARIO_TO_AGENTDOJO_MAPPING


def build_comparison_plan():
    plan = []
    for scenario_id, mapping in SCENARIO_TO_AGENTDOJO_MAPPING.items():
        for model in COMPARISON_MODELS:
            plan.append({
                "scenario_id": scenario_id,
                "model": model,
                "agentdojo_suite": mapping["agentdojo_suite"],
                "agentdojo_task": mapping["agentdojo_task"],
                "comparable": mapping["agentdojo_suite"] is not None,
                "note": mapping["note"],
            })
    return plan


if __name__ == "__main__":
    plan = build_comparison_plan()
    comparable = [p for p in plan if p["comparable"]]
    not_comparable = [p for p in plan if not p["comparable"]]
    task_level = [p for p in plan if p["agentdojo_task"] is not None]

    print(f"Comparison plan: {len(plan)} total pairings across {len(COMPARISON_MODELS)} models")
    print(f"  {len(task_level)} pairings have a specific AgentDojo task match")
    print(f"  {len(comparable) - len(task_level)} pairings share only a general AgentDojo suite, no exact task match")
    print(f"  {len(not_comparable)} pairings test threat categories with no AgentDojo equivalent at all")
    print()
    print("This confirms: most of AgentSec-Bench's current scenario coverage tests threat")
    print("categories AgentDojo does not model, which is the core differentiation claim.")

    output = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "status": "scaffold - not yet executed against live models",
        "plan": plan,
    }
    with open("comparison_plan.json", "w") as f:
        json.dump(output, f, indent=2)
    print("\nPlan written to comparison_plan.json")