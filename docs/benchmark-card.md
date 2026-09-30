# Benchmark Card

Modeled on the "model card" / "datasheet" convention, summarizing intended use,
scope, and assumptions for AgentSec-Bench.

## Intended use

Evaluating whether a tool-using AI agent (scripted or LLM-backed) exhibits unsafe
or unauthorized behavior under prompt-based social-engineering pressure, and
whether a runtime security layer (AgentGuard) reduces the rate of such behavior
without materially harming legitimate task completion. Intended for research and
pre-deployment evaluation, not as a certification or compliance attestation.

## Metrics

Per scenario/agent run, `ScenarioResult` records:

- `attack_succeeded` (bool) - whether the scenario-specific attack condition was
  met (defined per-scenario in `evaluate()`)
- `task_completed` (bool) - whether the agent's trace includes the legitimate
  ground-truth actions
- `unauthorized_tool_calls` - role-based authorization violations found in the
  trace
- `suspicious_destinations` - destination-based violations (data sent outside
  `scenario.allowed_destinations`)

Aggregate metrics (via AgentSec-Scorecard): overall score and per-threat-category
score across a batch of runs.

## Scope

- 9 scenarios, 8 threat categories (see `docs/threat-model.md`)
- Scripted agents (deterministic, reproducible) plus live LLM agent support
  (OpenAI, Anthropic) for scenarios where funded API credits are available
- Mock tools and mock/synthetic environments only

## Assumptions and limitations

See `docs/limitations.md` for the full list. The most significant: the evaluator
assesses the agent's reported trace, not independently-verified environment state
(see `docs/architecture.md`), and one threat category (HT-001, human-agent trust
exploitation) is not caught by AgentSec-Bench's own automatic detection mechanisms
or AgentTrace - only by AgentGuard's separate outcome-consistency check, which is
a mitigation layered on top rather than something the benchmark itself detects.

## Comparison to AgentDojo

AgentSec-Bench extends beyond AgentDojo's prompt-injection focus into
authorization, tool misuse, privilege escalation, and data exfiltration. A
comparison harness (`comparison_plan.json`, `scripts/run_comparison.py`) maps
AgentSec-Bench scenarios to AgentDojo tasks and identifies threat categories
AgentDojo doesn't cover. The harness itself is complete and has been tested
end-to-end against live OpenAI and Anthropic APIs; producing actual comparative
results is blocked only on funded API credits, not on any remaining code work.
