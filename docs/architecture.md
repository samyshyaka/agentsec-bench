# Architecture

AgentSec-Bench is built around four core interfaces, defined in `agentsec_bench/core/`:

- **Scenario** - a single attack/misuse case. Declares `id`, `threat_category`,
  `prompt` (the instruction given to the agent under test), `owasp_control_id`,
  and optionally `allowed_destinations` (for destination-based checks). Implements
  `ground_truth(pre_env)` - the correct, non-attacked tool-call sequence - and
  `evaluate(trace, pre_env, post_env)`, which inspects the trace the agent actually
  produced and returns a `ScenarioResult` (`attack_succeeded`, `task_completed`).
- **Agent** - implements `query(prompt, tools, env)`, returning `(messages, trace)`
  where `trace` is a `list[ToolCall]`. Agents in this repo are scripted stand-ins
  (a "bad" version that falls for the attack, a "good" version that doesn't) plus
  LLM-backed implementations (`llm_agent.py`, `llm_agent_anthropic.py`) for live
  testing against real models.
- **Tool** - declares `name`, `description`, `parameters` (a pydantic model),
  `permission` (`ToolPermission`: `required_role`, `risk_tier`), and a `run`
  callable.
- **Evaluator** - `Evaluator.run(scenario, agent, env)` calls `agent.query(...)`
  directly and evaluates the returned trace. Two automatic detection mechanisms
  run on top of `scenario.evaluate()`:
  - Role-based: a tool call whose `required_role` the agent doesn't have is
    recorded in `result.unauthorized_tool_calls`.
  - Destination-based (`Evaluator._check_destinations()`): any `ToolCall.args`
    key in `["recipient", "email", "destination", "to"]` not in
    `scenario.allowed_destinations` is recorded in `result.suspicious_destinations`.

## An important mechanical detail

`Evaluator.run()` evaluates the agent's *claimed* trace - it does not call each
`Tool.run()` to actually execute the action against the environment. `pre_env` and
`post_env` are the same object unless an agent mutates `env` directly (no agent in
this repo does). This means scenario design has to work entirely through what the
agent's trace claims happened, not through real state mutation - `evaluate()`
methods check `trace` contents (which tools were called, with what args), not
environment state before/after. This is a deliberate simplification for a scripted-
agent benchmark, not a bug, but it's worth understanding before extending the
framework: a scenario that tried to check `post_env` for a state change would
never see one.

## How the other five projects plug in

- **AgentTrace** (`agenttrace.analyzer.SequenceAnalyzer`) analyzes the same trace
  independently, looking for suspicious call sequences rather than authorization
  violations.
- **AgentGuard** (`agentguard.guard.AgentGuard`) is a separate, pre-execution
  authorization layer - given a proposed tool call, `AgentGuard.check()` decides
  allow/deny *before* anything runs, based on `ToolPolicy` rules (role, max value,
  destination, call count). It also has `check_outcome()`, a distinct check for
  whether a tool call's *claimed* outcome matches reality (`actual_state`), used
  for HT-001 - see `docs/threat-model.md`.
- **AgentSec-Scorecard** turns a batch of `ScenarioResult` rows into an overall
  score and per-category breakdown.
- **AgentSec-Crosswalk** maps each scenario's `threat_category` /
  `owasp_control_id` to OWASP ASI controls and NIST AI RMF functions, and reports
  coverage gaps.

`scripts/integration_demo.py` runs all of the above together in one pass and is
the most complete illustration of how the pieces connect.
