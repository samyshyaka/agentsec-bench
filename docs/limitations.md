# Limitations

This is a more detailed companion to the "Not yet done" section in `README.md`.

- **HT-001 detection gap.** Of the 9 scenarios, HT-001 (human-agent trust
  exploitation) is the one case where a successful attack is caught by neither of
  AgentSec-Bench's own detection mechanisms (role-based or destination-based) nor
  by AgentTrace's `SequenceAnalyzer` - it shows up as a `0.0/100` category score
  in the Scorecard summary from those signals alone. `scenario.evaluate()` itself
  does correctly flag `attack_succeeded` for HT-001 (it checks whether
  `report_status`'s claimed status matches what actually happened), so the
  benchmark's ground-truth scoring is not blind to it - but the two *automatic*
  secondary signals (unauthorized tool calls, suspicious destinations) never
  trigger for this category, because reporting a false status is neither an
  unauthorized tool call nor a bad destination. AgentGuard's outcome-consistency
  check (`check_outcome`/`enforce_outcome`) is a working mitigation for this,
  wired into `scripts/integration_demo.py`, but it's a separate runtime layer, not
  a fix to AgentSec-Bench's own detection mechanisms.
- **No live baseline comparison results yet.** The AgentDojo comparison harness
  is complete and tested end-to-end against real OpenAI/Anthropic APIs, but
  producing actual results is blocked on funded API credits.
- **Trace-trust assumption.** The evaluator assesses the trace an agent reports,
  not independently-verified environment state (see the "important mechanical
  detail" in `docs/architecture.md`). A scenario or detection mechanism that
  assumed real state mutation would not work as intended under this design.
- **Scenario breadth.** 9 scenarios across 8 threat categories is a starting set,
  not exhaustive coverage of either the OWASP ASI Top 10 or the NIST AI RMF -
  `agentsec_crosswalk`'s gap report currently shows 3 of 10 OWASP ASI controls
  with no scenario coverage at all (see that repo's `crosswalk_gaps.json`).
- **Single-agent scope.** Scenarios evaluate one agent's behavior at a time;
  multi-agent collusion or handoff attacks are not modeled.
- **Docker reproducibility untested end-to-end.** A `Dockerfile` is provided and
  kept in sync with the current `scripts/` layout, but has not yet had a full
  build-and-run pass completed on any machine (blocked locally by a Windows
  Update servicing error) - worth verifying in CI or elsewhere before relying on
  it for reproducibility claims.
