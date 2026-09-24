"""
Runs the baseline comparison: AgentSec-Bench results vs. AgentDojo results,
across the same models, for scenarios that have a genuine equivalent.

Two parts:
1. build_comparison_plan() - always runs, no API keys needed. Produces
   comparison_plan.json describing which scenarios are/aren't comparable
   to AgentDojo.
2. run_live_comparison() - actually executes each of the 9 scenarios
   against live LLM agents (OpenAI / Anthropic) for each model in
   COMPARISON_MODELS. Requires funded API keys in .env
   (OPENAI_API_KEY / ANTHROPIC_API_KEY). If keys are missing, this
   prints a clear message and exits without crashing - it does not
   run partially or produce bad data.
"""

import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

from comparison_config import COMPARISON_MODELS, SCENARIO_TO_AGENTDOJO_MAPPING

from agentsec_bench.core.environment import TaskEnvironment
from agentsec_bench.core.environment_inbox import InboxEnvironment
from agentsec_bench.tools.tools_expense import list_expenses_tool, approve_payment_tool
from agentsec_bench.tools.tools_refund import lookup_order_tool, issue_refund_tool
from agentsec_bench.tools.tools_inbox import summarize_inbox_tool, forward_email_tool
from agentsec_bench.scenarios.scenarios_expense import UnauthorizedApprovalScenario
from agentsec_bench.scenarios.scenarios_ambiguous import AmbiguousRefundScenario
from agentsec_bench.scenarios.scenarios_injection import InboxInjectionScenario
from agentsec_bench.core.evaluator import Evaluator

from agentsec_bench.core.environment_crm import CRMEnvironment
from agentsec_bench.tools.tools_crm import lookup_customer_tool, send_message_tool
from agentsec_bench.scenarios.scenarios_exfiltration import CustomerDataExfiltrationScenario

from agentsec_bench.tools.tools_admin import view_user_tool, grant_admin_tool
from agentsec_bench.scenarios.scenarios_privilege import PrivilegeEscalationScenario

from agentsec_bench.tools.tools_devops import restart_service_tool, run_shell_command_tool
from agentsec_bench.scenarios.scenarios_code_execution import UnexpectedCodeExecutionScenario

from agentsec_bench.tools.tools_workspace import list_files_tool, delete_file_tool
from agentsec_bench.scenarios.scenarios_rogue import RogueAgentScenario

from agentsec_bench.tools.tools_vendor import lookup_vendor_notes_tool, approve_vendor_payment_tool
from agentsec_bench.scenarios.scenarios_memory_poisoning import MemoryPoisoningScenario

from agentsec_bench.tools.tools_reporting import run_backup_tool, report_status_tool
from agentsec_bench.scenarios.scenarios_trust_exploitation import TrustExploitationScenario

from agentsec_bench.agents.llm_agent import OpenAIAgent
from agentsec_bench.agents.llm_agent_anthropic import AnthropicAgent

load_dotenv()

# Same 9 scenarios as run_test.py's TEST_MATRIX, but without the scripted
# stand-in agents - here the agent is a live LLM, chosen per model at run time.
SCENARIO_MATRIX = [
    (
        UnauthorizedApprovalScenario(),
        TaskEnvironment,
        [list_expenses_tool, approve_payment_tool],
    ),
    (
        AmbiguousRefundScenario(),
        TaskEnvironment,
        [lookup_order_tool, issue_refund_tool],
    ),
    (
        InboxInjectionScenario(),
        InboxEnvironment,
        [summarize_inbox_tool, forward_email_tool],
    ),
    (
        CustomerDataExfiltrationScenario(),
        CRMEnvironment,
        [lookup_customer_tool, send_message_tool],
    ),
    (
        PrivilegeEscalationScenario(),
        TaskEnvironment,
        [view_user_tool, grant_admin_tool],
    ),
    (
        UnexpectedCodeExecutionScenario(),
        TaskEnvironment,
        [restart_service_tool, run_shell_command_tool],
    ),
    (
        RogueAgentScenario(),
        TaskEnvironment,
        [list_files_tool, delete_file_tool],
    ),
    (
        MemoryPoisoningScenario(),
        TaskEnvironment,
        [lookup_vendor_notes_tool, approve_vendor_payment_tool],
    ),
    (
        TrustExploitationScenario(),
        TaskEnvironment,
        [run_backup_tool, report_status_tool],
    ),
]


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


def check_api_keys(models):
    """
    Returns a list of human-readable problems. Empty list means all keys
    needed for the given models are present. Never raises - just reports.
    """
    problems = []
    needs_openai = any(m.startswith("gpt-") for m in models)
    needs_anthropic = any(m.startswith("claude-") for m in models)

    if needs_openai and not os.environ.get("OPENAI_API_KEY"):
        problems.append(
            "OPENAI_API_KEY is not set (required for models: "
            + ", ".join(m for m in models if m.startswith("gpt-")) + ")"
        )
    if needs_anthropic and not os.environ.get("ANTHROPIC_API_KEY"):
        problems.append(
            "ANTHROPIC_API_KEY is not set (required for models: "
            + ", ".join(m for m in models if m.startswith("claude-")) + ")"
        )
    return problems


def make_agent(model):
    if model.startswith("gpt-"):
        return OpenAIAgent(model=model)
    if model.startswith("claude-"):
        return AnthropicAgent(model=model)
    raise ValueError(f"Don't know which live agent class to use for model: {model}")


def run_live_comparison(scenario_matrix, models):
    """
    Runs every scenario in scenario_matrix against every model, using a
    live LLM agent. Each run is wrapped in try/except so one bad call
    (rate limit, network error, API change) doesn't take down the whole
    comparison - it's recorded as an error row instead.
    """
    results = []
    for scenario, env_factory, tools in scenario_matrix:
        mapping = SCENARIO_TO_AGENTDOJO_MAPPING.get(scenario.id, {})
        for model in models:
            row = {
                "scenario": scenario.id,
                "category": scenario.threat_category.value,
                "model": model,
                "agentdojo_suite": mapping.get("agentdojo_suite"),
                "agentdojo_task": mapping.get("agentdojo_task"),
            }
            try:
                agent = make_agent(model)
                evaluator = Evaluator(tools=tools)
                env = env_factory()
                result = evaluator.run(scenario, agent, env)
                row.update({
                    "status": "ok",
                    "task_completed": result.task_completed,
                    "attack_succeeded": result.attack_succeeded,
                    "unauthorized_tool_calls": result.unauthorized_tool_calls,
                    "suspicious_destinations": result.suspicious_destinations,
                })
            except Exception as e:
                row.update({
                    "status": "error",
                    "error": str(e),
                })
            results.append(row)
    return results


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

    print()
    print("Checking for live model API access...")
    problems = check_api_keys(COMPARISON_MODELS)
    if problems:
        print("Live comparison SKIPPED - missing API keys:")
        for p in problems:
            print(f"  - {p}")
        print()
        print("Add the missing key(s) to your .env file and re-run this script")
        print("to execute the live comparison. The plan above is unaffected.")
    else:
        print("API keys found. Running live comparison against all 9 scenarios...")
        live_results = run_live_comparison(SCENARIO_MATRIX, COMPARISON_MODELS)
        live_output = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "models": COMPARISON_MODELS,
            "results": live_results,
        }
        with open("comparison_results.json", "w") as f:
            json.dump(live_output, f, indent=2)
        errors = [r for r in live_results if r["status"] == "error"]
        print(f"\nLive comparison complete: {len(live_results)} runs, {len(errors)} errors.")
        print("Results written to comparison_results.json")