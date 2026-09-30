# Contributing to AgentSec-Bench

Thanks for your interest in contributing. This project is part of the Open Agent
Security Initiative.

## Getting set up

Prerequisites: Python 3.12 (see `.python-version`) and
[uv](https://docs.astral.sh/uv/) for dependency management.

    git clone https://github.com/samyshyaka/agentsec-bench.git
    cd agentsec-bench
    uv sync

## Running the test suite

Before opening a pull request, make sure the full test suite passes:

    uv run pytest -v

For scenario changes specifically, also run the ground-truth sanity check:

    uv run python scripts/check_scenarios.py

## Project layout

See the "Project layout" section of `README.md` for where things live
(`agentsec_bench/core/`, `agentsec_bench/scenarios/`, `agentsec_bench/tools/`,
`agentsec_bench/agents/`, `tests/`).

## Adding a new scenario

A new scenario needs, at minimum:

1. A `Scenario` subclass with `id`, `threat_category`, `prompt`,
   `owasp_control_id`, `ground_truth()`, and `evaluate()` (see
   `agentsec_bench/core/scenario.py` for the interface).
2. At least one "bad" agent that triggers the attack and one "good" agent that
   doesn't, so both detection and false-positive behavior are covered.
3. A test file under `tests/` that exercises `Evaluator.check_scenario()` as a
   ground-truth sanity check, plus a test per agent.

## Pull requests

- Keep PRs focused on one change.
- Include what you tested and how in the PR description.
- Do not commit changes directly to `staging` or `main` - work from a feature
  branch and open a PR.

## Code of conduct

Be respectful and constructive. This is a security research project; good-faith
disagreement about threat models and detection approaches is expected and welcome.
