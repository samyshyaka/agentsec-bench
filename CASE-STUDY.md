# Open Agent Security Initiative: A Case Study in Testing Agent Security End-to-End

## The problem

Tool-using AI agents fail in ways that don't show up in normal functional
testing: an agent approves a payment it wasn't authorized to approve, forwards
a customer's data to an address a hidden prompt-injected instruction
supplied, or trusts a poisoned memory entry over its own better judgment.
Existing benchmarks like AgentDojo focus heavily on prompt injection. The
Open Agent Security Initiative extends that coverage into authorization,
tool misuse, privilege escalation, data exfiltration, and four other threat
patterns - and, just as importantly, builds the runtime and reporting layer
around the benchmark so the findings are actionable rather than just a
research artifact.

## The six projects

- **AgentSec-Bench** - the evaluation core. Defines the Scenario / Agent /
  Tool / Evaluator interfaces, 9 concrete attack scenarios across 8 threat
  categories, and two independent detection mechanisms (role-based
  authorization checks and destination-based checks) that catch different
  classes of failure.
- **AgentTrace** - runtime anomaly detection over an agent's tool-call
  sequence: flags suspicious read-then-external-action patterns,
  AgentSec-Bench's own unauthorized-call and suspicious-destination
  findings, and excessive repeated tool calls.
- **AgentGuard** - policy enforcement that sits in front of tool execution
  and blocks a disallowed call *before* it happens, rather than only
  detecting it after the fact. Supports role-based and destination-based
  policies, plus a "requires confirmation" policy type for calls that
  should pause for human sign-off rather than being outright blocked.
- **AgentSec-Scorecard** - turns a batch of scenario results into a single
  security score (percentage of attempted attacks actually caught) plus a
  per-category breakdown, and tracks that score's trend across runs over
  time via a committed history file.
- **AgentSec-Crosswalk** - maps each scenario to the OWASP Agentic Security
  Initiative (ASI) control and NIST AI RMF function(s) it exercises, built
  directly from live scenario instances so it can't silently drift out of
  sync, and reports which controls/functions currently have zero scenario
  coverage.
- **CriticalAgent-Blueprints** - sector reference architectures (not yet
  cross-referenced with the other five projects' output - see "What's next"
  below).

## What ties them together

`agentsec-bench/scripts/integration_demo.py` runs all 9 scenarios end to
end and demonstrates every other project consuming that same run:

1. **AgentSec-Bench** evaluates all 9 scenarios against both a
   misbehaving/overreaching agent and a well-behaved counterpart (18
   evaluations total).
2. **AgentTrace** analyzes every resulting trace for runtime anomaly
   findings, independent of AgentSec-Bench's own scenario-level checks.
3. **AgentGuard** re-runs the 4 scenarios it has policies configured for
   and shows the attack being blocked before execution, not just flagged
   afterward.
4. **AgentSec-Scorecard** scores the full run and records it to a history
   file, so score trend is visible across runs.
5. **AgentSec-Crosswalk** maps all 9 scenarios to OWASP ASI / NIST AI RMF
   and reports coverage gaps.

## Results from a real run

- **9 scenarios, 18 evaluations.** Every misbehaving agent's attack
  succeeded; every well-behaved counterpart's did not - confirming the
  scenarios and agents are correctly differentiated.
- **AgentGuard blocked 4/4** of the attack patterns it has policies
  configured for, before the tool call executed.
- **Overall Security Score: 88.9/100** across all 9 threat categories.
- **OWASP ASI coverage: 7 of 10 controls** exercised by at least one
  scenario (ASI01, ASI02, ASI03, ASI05, ASI06, ASI09, ASI10). ASI04, ASI07,
  and ASI08 currently have zero scenario coverage.
- **NIST AI RMF coverage: all 4 functions** (Govern, Map, Measure, Manage)
  exercised by at least one scenario.

## Known gaps

The integration demo surfaced a genuine, currently-unaddressed detection
gap rather than just a coverage statistic: **HT-001** (human/agent trust
exploitation) is the one scenario, of the 9, where a successful attack is
caught by neither of AgentSec-Bench's own detection mechanisms nor by
AgentTrace's runtime analysis. It scores 0/100 in the Scorecard breakdown.
Surfacing this kind of gap - not just "the benchmark ran" but "here is
specifically what it still can't catch" - is the actual value of building
the detection and reporting layers together rather than the scenarios
alone.

Separately, OWASP ASI controls ASI04, ASI07, and ASI08 have no scenario
coverage yet, and the OWASP ASI control list used for that gap report
should be checked against the authoritative OWASP ASI reference document
if that list is ever revised.

## What's next

- Detection coverage for HT-001.
- Scenario coverage for OWASP ASI04, ASI07, ASI08.
- Wiring CriticalAgent-Blueprints' sector reference architectures into the
  same crosswalk/gap-report pipeline, so a coverage gap can be traced to
  which sector blueprints it affects.
- Live baseline comparison against AgentDojo (harness built and tested
  end-to-end against real OpenAI/Anthropic APIs; blocked only on funded
  API credits).