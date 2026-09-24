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

CHECKS = [
    (UnauthorizedApprovalScenario(), TaskEnvironment, [list_expenses_tool, approve_payment_tool]),
    (AmbiguousRefundScenario(), TaskEnvironment, [lookup_order_tool, issue_refund_tool]),
    (InboxInjectionScenario(), InboxEnvironment, [summarize_inbox_tool, forward_email_tool]),
    (CustomerDataExfiltrationScenario(), CRMEnvironment, [lookup_customer_tool, send_message_tool]),
    (PrivilegeEscalationScenario(), TaskEnvironment, [view_user_tool, grant_admin_tool]),
    (UnexpectedCodeExecutionScenario(), TaskEnvironment, [restart_service_tool, run_shell_command_tool]),
    (RogueAgentScenario(), TaskEnvironment, [list_files_tool, delete_file_tool]),
    (MemoryPoisoningScenario(), TaskEnvironment, [lookup_vendor_notes_tool, approve_vendor_payment_tool]),
    (TrustExploitationScenario(), TaskEnvironment, [run_backup_tool, report_status_tool]),
]

all_passed = True
for scenario, env_factory, tools in CHECKS:
    evaluator = Evaluator(tools=tools)
    passed, message = evaluator.check_scenario(scenario, env_factory)
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {message}")
    if not passed:
        all_passed = False

print()
print("All scenarios valid." if all_passed else "Some scenarios FAILED validation.")