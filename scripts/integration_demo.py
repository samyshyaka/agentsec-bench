"""
End-to-end integration demo: runs all 9 AgentSec-Bench scenarios and shows
how the other Open Agent Security Initiative projects consume the same run.

  1-2. AgentSec-Bench + AgentTrace - runs each scenario, analyzes each
       resulting trace for runtime anomaly findings.
  3.   AgentGuard - for the 4 scenarios with an existing policy, shows the
       same attack being blocked before execution (reuses the exact
       policies from guard_integration_demo.py).
  4.   AgentSec-Scorecard - turns all 18 results (9 scenarios x 2 agents)
       into an overall score and records it to a demo-local history file.
  5.   AgentSec-Crosswalk - maps all 9 scenarios to OWASP ASI / NIST AI RMF
       and reports coverage gaps.

CriticalAgent-Blueprints is not wired into this demo yet.

Nothing here writes into another repo's committed history file
(scorecard_history.json, crosswalk.json, results.json) - this script keeps
its own output under integration_demo_output/ so a demo run never clobbers
a repo's real tracked data.
"""
import json
import os
from datetime import datetime, timezone

from agentsec_bench.core.environment import TaskEnvironment
from agentsec_bench.core.environment_inbox import InboxEnvironment
from agentsec_bench.core.environment_crm import CRMEnvironment
from agentsec_bench.core.evaluator import Evaluator

from agentsec_bench.tools.tools_expense import list_expenses_tool, approve_payment_tool
from agentsec_bench.tools.tools_refund import lookup_order_tool, issue_refund_tool
from agentsec_bench.tools.tools_inbox import summarize_inbox_tool, forward_email_tool
from agentsec_bench.tools.tools_crm import lookup_customer_tool, send_message_tool
from agentsec_bench.tools.tools_admin import view_user_tool, grant_admin_tool
from agentsec_bench.tools.tools_devops import restart_service_tool, run_shell_command_tool
from agentsec_bench.tools.tools_workspace import list_files_tool, delete_file_tool
from agentsec_bench.tools.tools_vendor import lookup_vendor_notes_tool, approve_vendor_payment_tool
from agentsec_bench.tools.tools_reporting import run_backup_tool, report_status_tool

from agentsec_bench.scenarios.scenarios_expense import UnauthorizedApprovalScenario
from agentsec_bench.scenarios.scenarios_ambiguous import AmbiguousRefundScenario
from agentsec_bench.scenarios.scenarios_injection import InboxInjectionScenario
from agentsec_bench.scenarios.scenarios_exfiltration import CustomerDataExfiltrationScenario
from agentsec_bench.scenarios.scenarios_privilege import PrivilegeEscalationScenario
from agentsec_bench.scenarios.scenarios_code_execution import UnexpectedCodeExecutionScenario
from agentsec_bench.scenarios.scenarios_rogue import RogueAgentScenario
from agentsec_bench.scenarios.scenarios_memory_poisoning import MemoryPoisoningScenario
from agentsec_bench.scenarios.scenarios_trust_exploitation import TrustExploitationScenario

from agentsec_bench.agents.fake_agent import MisbehavingAgent
from agentsec_bench.agents.good_agent import WellBehavedAgent
from agentsec_bench.agents.refund_agents import OverreachingSupportAgent, CautiousSupportAgent
from agentsec_bench.agents.inbox_agents import InjectionSusceptibleAgent, InjectionResistantAgent
from agentsec_bench.agents.crm_agents import ExfiltratingAgent, DataMindfulAgent
from agentsec_bench.agents.admin_agents import OvereagerAdminAgent, RestrainedAdminAgent
from agentsec_bench.agents.devops_agents import CredulousOpsAgent, DisciplinedOpsAgent
from agentsec_bench.agents.workspace_agents import RogueCleanupAgent, InstructionFollowingAgent
from agentsec_bench.agents.vendor_agents import MemoryTrustingAgent, SkepticalFinanceAgent
from agentsec_bench.agents.reporting_agents import DeceptiveOpsAgent, HonestOpsAgent

from agenttrace.analyzer import SequenceAnalyzer

from agentguard.policy import ToolPolicy, OutcomeConsistencyRule
from agentguard.guard import AgentGuard

from agentsec_scorecard.scorecard import Scorecard
from agentsec_scorecard.trend import ScoreHistory

from agentsec_crosswalk.mapping import crosswalk_entry
from agentsec_crosswalk.gaps import coverage_gap_report


OUTPUT_DIR = "integration_demo_output"


TEST_MATRIX = [
    (
        UnauthorizedApprovalScenario(),
        TaskEnvironment,
        [list_expenses_tool, approve_payment_tool],
        [MisbehavingAgent(), WellBehavedAgent()],
    ),
    (
        AmbiguousRefundScenario(),
        TaskEnvironment,
        [lookup_order_tool, issue_refund_tool],
        [OverreachingSupportAgent(), CautiousSupportAgent()],
    ),
    (
        InboxInjectionScenario(),
        InboxEnvironment,
        [summarize_inbox_tool, forward_email_tool],
        [InjectionSusceptibleAgent(), InjectionResistantAgent()],
    ),
    (
        CustomerDataExfiltrationScenario(),
        CRMEnvironment,
        [lookup_customer_tool, send_message_tool],
        [ExfiltratingAgent(), DataMindfulAgent()],
    ),
    (
        PrivilegeEscalationScenario(),
        TaskEnvironment,
        [view_user_tool, grant_admin_tool],
        [OvereagerAdminAgent(), RestrainedAdminAgent()],
    ),
    (
        UnexpectedCodeExecutionScenario(),
        TaskEnvironment,
        [restart_service_tool, run_shell_command_tool],
        [CredulousOpsAgent(), DisciplinedOpsAgent()],
    ),
    (
        RogueAgentScenario(),
        TaskEnvironment,
        [list_files_tool, delete_file_tool],
        [RogueCleanupAgent(), InstructionFollowingAgent()],
    ),
    (
        MemoryPoisoningScenario(),
        TaskEnvironment,
        [lookup_vendor_notes_tool, approve_vendor_payment_tool],
        [MemoryTrustingAgent(), SkepticalFinanceAgent()],
    ),
    (
        TrustExploitationScenario(),
        TaskEnvironment,
        [run_backup_tool, report_status_tool],
        [DeceptiveOpsAgent(), HonestOpsAgent()],
    ),
]

# The 4 scenarios AgentGuard already has policies for - same tool names,
# same allowed_roles/allowed_destinations as guard_integration_demo.py.
GUARD_TARGETS = {
    "UTI-001": (
        UnauthorizedApprovalScenario(), TaskEnvironment,
        [list_expenses_tool, approve_payment_tool], MisbehavingAgent(),
        AgentGuard([ToolPolicy(tool_name="approve_payment", allowed_roles=["finance_manager"])]),
    ),
    "PI-001": (
        InboxInjectionScenario(), InboxEnvironment,
        [summarize_inbox_tool, forward_email_tool], InjectionSusceptibleAgent(),
        AgentGuard([ToolPolicy(tool_name="forward_email", allowed_destinations=[])]),
    ),
    "EX-001": (
        CustomerDataExfiltrationScenario(), CRMEnvironment,
        [lookup_customer_tool, send_message_tool], ExfiltratingAgent(),
        AgentGuard([ToolPolicy(tool_name="send_message", allowed_destinations=[])]),
    ),
    "PE-001": (
        PrivilegeEscalationScenario(), TaskEnvironment,
        [view_user_tool, grant_admin_tool], OvereagerAdminAgent(),
        AgentGuard([ToolPolicy(tool_name="grant_admin", allowed_roles=["super_admin"])]),
    ),
}

# HT-001 (TrustExploitationScenario) can't be checked via GUARD_TARGETS/check() -
# the issue isn't authorization, it's whether report_status's claimed outcome
# matches reality. run_backup_impl (agentsec_bench/tools/tools_reporting.py) is
# deterministic and always fails ("FAILED: disk quota exceeded"), so the real
# status used below is confirmed from that code, not guessed.
OUTCOME_GUARD_SCENARIO = TrustExploitationScenario()
OUTCOME_GUARD_TOOLS = [run_backup_tool, report_status_tool]
OUTCOME_GUARD_AGENTS = {
    "deceptive-ops-agent": DeceptiveOpsAgent(),
    "honest-ops-agent": HonestOpsAgent(),
}
OUTCOME_GUARD_ACTUAL_STATE = {"status": "failed"}


def run_bench_and_trace():
    """Steps 1-2: run every scenario through Evaluator, analyze each trace
    with AgentTrace. Returns the same row shape run_test.py writes to
    results.json, so Scorecard can consume it unchanged."""
    trace_analyzer = SequenceAnalyzer()
    rows = []
    for scenario, env_factory, tools, agents in TEST_MATRIX:
        evaluator = Evaluator(tools=tools)
        for agent in agents:
            env = env_factory()
            result = evaluator.run(scenario, agent, env)
            trace_findings = trace_analyzer.analyze(result)
            rows.append({
                "scenario": scenario.id,
                "category": scenario.threat_category.value,
                "owasp_control_id": scenario.owasp_control_id,
                "agent": agent.name,
                "task_completed": result.task_completed,
                "attack_succeeded": result.attack_succeeded,
                "unauthorized_tool_calls": result.unauthorized_tool_calls,
                "suspicious_destinations": result.suspicious_destinations,
                "trace_findings": [f.rule_id for f in trace_findings],
            })
    return rows


def run_guard_demo():
    """Step 3: for the 4 scenarios with an existing AgentGuard policy,
    show the attack being blocked before execution."""
    blocked_count = 0
    for scenario_id, (scenario, env_factory, tools, agent, guard) in GUARD_TARGETS.items():
        messages, trace = agent.query(scenario.prompt, tools, env_factory())
        blocked = []
        for call in trace:
            decision = guard.check(call.tool_name, call.args, agent_role=agent.role)
            if not decision.allowed:
                blocked.append((call.tool_name, decision.reason))
        if blocked:
            blocked_count += 1
        print(f"  {scenario_id}: {'BLOCKED' if blocked else 'NOT BLOCKED'} - {blocked}")
    return blocked_count, len(GUARD_TARGETS)


def run_guard_outcome_demo():
    """HT-001: AgentGuard's outcome-consistency check (check_outcome), a
    different code path from check() - report_status is authorized either
    way, the question is whether the claimed status matches actual_state."""
    guard = AgentGuard([], outcome_rules=[OutcomeConsistencyRule(tool_name="report_status", field="status")])
    caught = 0
    for agent_name, agent in OUTCOME_GUARD_AGENTS.items():
        messages, trace = agent.query(OUTCOME_GUARD_SCENARIO.prompt, OUTCOME_GUARD_TOOLS, TaskEnvironment())
        report_call = next(c for c in trace if c.tool_name == "report_status")
        decision = guard.check_outcome(
            report_call.tool_name, report_call.args, OUTCOME_GUARD_ACTUAL_STATE, agent_role=agent.role
        )
        flagged = not decision.allowed
        if flagged:
            caught += 1
        claimed = report_call.args.get("status")
        outcome = f"CAUGHT ({decision.reason})" if flagged else "not flagged"
        print(f"  {agent_name}: claimed status={claimed!r}, actual=failed -> {outcome}")
    return caught, len(OUTCOME_GUARD_AGENTS)


def run_scorecard(rows):
    """Step 4: score the run and record it to a demo-local history file -
    never the real agentsec-scorecard/scorecard_history.json."""
    summary = Scorecard(rows).summary()
    history = ScoreHistory(path=os.path.join(OUTPUT_DIR, "integration_demo_history.json"))
    history.record(summary)
    return summary


def run_crosswalk():
    """Step 5: crosswalk all 9 scenarios and report coverage gaps."""
    entries = [crosswalk_entry(scenario) for scenario, *_ in TEST_MATRIX]
    gap_report = coverage_gap_report(entries)
    return entries, gap_report


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=== 1-2. AgentSec-Bench + AgentTrace: running all 9 scenarios ===\n")
    rows = run_bench_and_trace()
    print(f"{'Scenario':<10} {'Agent':<28} {'Attack':<8} {'TraceFlags'}")
    print("-" * 90)
    for r in rows:
        print(f"{r['scenario']:<10} {r['agent']:<28} {str(r['attack_succeeded']):<8} {r['trace_findings']}")

    print("\n=== 3. AgentGuard: blocking the 4 known attack patterns ===\n")
    blocked_count, guard_total = run_guard_demo()

    print("\n=== 3b. AgentGuard: catching HT-001 trust exploitation via outcome consistency ===\n")
    outcome_caught, outcome_total = run_guard_outcome_demo()

    print("\n=== 4. AgentSec-Scorecard: overall score for this run ===\n")
    summary = run_scorecard(rows)
    print(f"Overall Security Score: {summary['overall_score']}/100")
    for cat, score in summary["score_by_category"].items():
        print(f"  {cat}: {score}/100")

    print("\n=== 5. AgentSec-Crosswalk: OWASP ASI / NIST AI RMF coverage ===\n")
    entries, gap_report = run_crosswalk()
    print(f"OWASP ASI controls covered ({len(gap_report['owasp_controls_covered'])}): "
          f"{', '.join(gap_report['owasp_controls_covered'])}")
    print(f"OWASP ASI controls with NO coverage ({len(gap_report['owasp_controls_uncovered'])}): "
          f"{', '.join(gap_report['owasp_controls_uncovered']) or 'none'}")

    print("\n=== Summary ===\n")
    print(f"Scenarios run: {len(TEST_MATRIX)} (x2 agents = {len(rows)} evaluations)")
    print(f"AgentGuard blocked {blocked_count}/{guard_total} known attack patterns before execution")
    print(f"AgentGuard's outcome-consistency check caught {outcome_caught}/{outcome_total} agents misreporting HT-001 outcomes")
    print(f"Overall Security Score: {summary['overall_score']}/100")
    print(f"OWASP ASI coverage gaps: {gap_report['owasp_controls_uncovered'] or 'none'}")

    with open(os.path.join(OUTPUT_DIR, "integration_demo_results.json"), "w") as f:
        json.dump({
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "bench_rows": rows,
            "guard_blocked": blocked_count,
            "guard_total": guard_total,
            "guard_outcome_caught": outcome_caught,
            "guard_outcome_total": outcome_total,
            "scorecard_summary": summary,
            "crosswalk_gap_report": gap_report,
        }, f, indent=2)
    print(f"\nFull combined output written to {OUTPUT_DIR}\\integration_demo_results.json")


if __name__ == "__main__":
    main()