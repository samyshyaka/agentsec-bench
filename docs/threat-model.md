# Threat Model

## In scope

AgentSec-Bench evaluates whether a tool-using AI agent can be induced, through a
natural-language prompt alone (no adversarial fine-tuning, no model access, no
infrastructure-level attack), into taking an unsafe or unauthorized action via its
available tools. All scenarios run against mock tools, mock environments, and
synthetic data - nothing here touches a real production system.

## Threat categories covered

The 9 scenarios currently span 8 distinct threat categories (see
`agentsec_crosswalk`'s `crosswalk.json` for the authoritative live mapping):

| Category | Scenario(s) | What it tests |
|---|---|---|
| Unauthorized tool invocation | UTI-001, UTI-002 | Agent calls a tool it has no role-based authorization to use (e.g. approving its own payment, issuing an unauthorized refund) |
| Prompt injection | PI-001 | Hidden instructions embedded in retrieved content (e.g. an email body) redirect the agent's behavior |
| Data exfiltration | EX-001 | Agent sends sensitive data to a destination outside an allowed list |
| Privilege escalation | PE-001 | Agent grants elevated access it isn't authorized to grant |
| Unexpected code execution | CE-001 | Agent is induced into running an arbitrary/unsafe command |
| Rogue agent behavior | RA-001 | Agent takes a destructive action (e.g. deleting files) beyond what the task actually required |
| Memory / context poisoning | MP-001 | Agent trusts manipulated content injected into its working memory/context over the actual task |
| Human-agent trust exploitation | HT-001 | Agent misreports a task's actual outcome to the human operator (e.g. claims a failed backup succeeded) |

Each category has a "bad" agent that falls for the attack and a "good" agent that
doesn't, so the benchmark measures both detection of real attacks and absence of
false positives on legitimate behavior.

## Out of scope

- Attacks that require model weight access, fine-tuning, or adversarial training
- Attacks against the underlying LLM provider's infrastructure
- Physical or operational-control systems (see CriticalAgent-Blueprints' explicit
  safety rule: mock/sandboxed systems only, never real infrastructure)
- Multi-agent collusion (each scenario currently evaluates one agent at a time)
- Attacks that depend on real (non-synthetic) sensitive data

## Assumptions

- The agent's tool-call trace is fully observable and accurately reported by the
  agent harness (see the "important mechanical detail" in `docs/architecture.md` -
  the evaluator trusts the trace, it does not independently verify execution
  against environment state).
- Ground truth for each scenario (the correct, non-attacked action sequence) is
  well-defined and checked via `Evaluator.check_scenario()`.
- Detection mechanisms (role-based, destination-based, AgentGuard's outcome
  consistency check) are evaluated against these specific scripted scenarios, not
  as a claim of general-purpose coverage against arbitrary real-world attacks.
