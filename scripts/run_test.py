import json
from datetime import datetime, timezone

from agentsec_bench.core.environment import TaskEnvironment
from agentsec_bench.core.environment_inbox import InboxEnvironment
from agentsec_bench.tools.tools_expense import list_expenses_tool, approve_payment_tool
from agentsec_bench.tools.tools_refund import lookup_order_tool, issue_refund_tool
from agentsec_bench.tools.tools_inbox import summarize_inbox_tool, forward_email_tool
from agentsec_bench.scenarios.scenarios_expense import UnauthorizedApprovalScenario
from agentsec_bench.scenarios.scenarios_ambiguous import AmbiguousRefundScenario
from agentsec_bench.scenarios.scenarios_injection import InboxInjectionScenario
from agentsec_bench.agents.fake_agent import MisbehavingAgent
from agentsec_bench.agents.good_agent import WellBehavedAgent
from agentsec_bench.agents.refund_agents import OverreachingSupportAgent, CautiousSupportAgent
from agentsec_bench.agents.inbox_agents import InjectionSusceptibleAgent, InjectionResistantAgent
from agentsec_bench.core.evaluator import Evaluator

from agentsec_bench.core.environment_crm import CRMEnvironment
from agentsec_bench.tools.tools_crm import lookup_customer_tool, send_message_tool
from agentsec_bench.scenarios.scenarios_exfiltration import CustomerDataExfiltrationScenario
from agentsec_bench.agents.crm_agents import ExfiltratingAgent, DataMindfulAgent



from agentsec_bench.tools.tools_admin import view_user_tool, grant_admin_tool
from agentsec_bench.scenarios.scenarios_privilege import PrivilegeEscalationScenario
from agentsec_bench.agents.admin_agents import OvereagerAdminAgent, RestrainedAdminAgent

from agentsec_bench.tools.tools_devops import restart_service_tool, run_shell_command_tool
from agentsec_bench.scenarios.scenarios_code_execution import UnexpectedCodeExecutionScenario
from agentsec_bench.agents.devops_agents import CredulousOpsAgent, DisciplinedOpsAgent

from agentsec_bench.tools.tools_workspace import list_files_tool, delete_file_tool
from agentsec_bench.scenarios.scenarios_rogue import RogueAgentScenario
from agentsec_bench.agents.workspace_agents import RogueCleanupAgent, InstructionFollowingAgent

from agentsec_bench.tools.tools_vendor import lookup_vendor_notes_tool, approve_vendor_payment_tool
from agentsec_bench.scenarios.scenarios_memory_poisoning import MemoryPoisoningScenario
from agentsec_bench.agents.vendor_agents import MemoryTrustingAgent, SkepticalFinanceAgent

from agentsec_bench.tools.tools_reporting import run_backup_tool, report_status_tool
from agentsec_bench.scenarios.scenarios_trust_exploitation import TrustExploitationScenario
from agentsec_bench.agents.reporting_agents import DeceptiveOpsAgent, HonestOpsAgent


from agenttrace.analyzer import SequenceAnalyzer
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

results_summary = []
trace_analyzer = SequenceAnalyzer()

for scenario, env_factory, tools, agents in TEST_MATRIX:
    evaluator = Evaluator(tools=tools)
    for agent in agents:
        env = env_factory()
        result = evaluator.run(scenario, agent, env)
        trace_findings = trace_analyzer.analyze(result)
        results_summary.append({
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
print(f"{'Scenario':<10} {'Category':<28} {'Agent':<28} {'Attack':<8} {'RoleFlag':<20} {'TraceFlags':<28} Destinations")
print("-" * 160)
for r in results_summary:
    print(f"{r['scenario']:<10} {r['category']:<28} {r['agent']:<28} "
          f"{str(r['attack_succeeded']):<8} {str(r['unauthorized_tool_calls']):<20} "
          f"{str(r['trace_findings']):<28} {r['suspicious_destinations']}")
output = {
    "run_timestamp": datetime.now(timezone.utc).isoformat(),
    "results": results_summary,
}

with open("results.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"\nResults written to results.json ({len(results_summary)} rows)")