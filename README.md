# AgentSec-Bench

A reproducible security evaluation framework for tool-using AI agents,
extending beyond AgentDojo's prompt-injection focus into authorization,
tool misuse, privilege escalation, and data exfiltration.

## Status

Working prototype. Currently supports:

- Core Scenario / Agent / Tool / Evaluator interfaces
-  9 scenarios across 4 threat patterns::
  - Unauthorized tool invocation (payment approval, refund authorization, privilege escalation)
  - Prompt injection (hidden instructions in retrieved content)
  - Data exfiltration (sensitive data sent to unauthorized destinations)
- Two independent detection mechanisms:
  - Role-based authorization checks
  - Destination-based checks (catches cases role checks alone miss)
- 26 automated tests (ground-truth validation + agent behavior checks)
- JSON results export with OWASP control mapping
- HTML report generation

## Project layout

- `agentsec_bench/core/` — the Scenario, Agent, Tool, and Evaluator base interfaces everything else builds on.
- `agentsec_bench/scenarios/` — the scenario definitions (the attack/misuse cases being tested).
- `agentsec_bench/tools/` — the mock tools scenarios use (expense, refund, inbox, CRM, admin, devops, workspace, vendor, reporting).
- `agentsec_bench/agents/` — the agent implementations under test, including the scripted stand-ins and the LLM-backed agents (`llm_agent.py`, `llm_agent_anthropic.py`).
- `tests/` — the automated test suite (ground-truth validation + agent behavior checks).
- `run_test.py` — runs all scenarios end-to-end.
- `check_scenarios.py` — validates scenario ground truth.
- `generate_report.py` — produces the HTML report.
- `run_comparison.py` / `comparison_config.py` — baseline comparison harness (e.g. against AgentDojo).
- `guard_integration_demo.py` — demonstrates AgentGuard blocking a call at runtime that AgentSec-Bench detects after the fact.

## Not yet done

- Live LLM agent evaluation (OpenAI and Anthropic integrations are built,
  pending account funding)
- Baseline comparison against AgentDojo
- Docker-based reproducibility
- Broader scenario coverage

## Running it
    uv sync
    uv run python scripts/run_test.py        # run all scenarios
    uv run python scripts/check_scenarios.py  # validate ground truth
    uv run pytest -v                          # run test suite
    uv run python scripts/generate_report.py  # produce report.html