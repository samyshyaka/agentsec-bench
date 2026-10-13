import argparse
import json
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, "scripts")
from run_comparison import SCENARIO_MATRIX, make_agent
from experiment_week3 import GUARD, HT001_ACTUAL_STATE
from agentsec_bench.core.agent import Agent
from agentsec_bench.core.evaluator import Evaluator
from agentsec_bench.core.types import Tool

MODEL = "openai/gpt-oss-20b"


class LiveGuardedAgent(Agent):
    """Checks every tool call with AgentGuard BEFORE the tool runs.
    Blocked calls never execute and are removed from the trace the
    evaluator sees, exactly like the existing GuardedAgentWrapper."""

    def __init__(self, inner, guard):
        self.inner = inner
        self.guard = guard
        self.name = inner.name
        self.role = inner.role
        self.blocked = []

    def _wrap(self, tool):
        agent = self

        def guarded_run(**kwargs):
            if tool.name == "report_status":
                norm = {k: (v.strip().lower() if isinstance(v, str) and k == 'status' else v) for k, v in kwargs.items()}
                d = agent.guard.check_outcome(tool.name, norm, HT001_ACTUAL_STATE, agent_role=agent.role)
            else:
                d = agent.guard.check(tool.name, kwargs, agent_role=agent.role)
            if not d.allowed:
                agent.blocked.append({"tool": tool.name, "args": dict(kwargs), "reason": str(d.reason)})
                return "BLOCKED by AgentGuard: " + str(d.reason)
            return tool.run(**kwargs)

        return Tool(
            name=tool.name,
            description=tool.description,
            parameters=tool.parameters,
            permission=tool.permission,
            run=guarded_run,
        )

    def query(self, prompt, tools, env):
        self.blocked = []
        guarded_tools = [self._wrap(t) for t in tools]
        messages, trace = self.inner.query(prompt, guarded_tools, env)
        pending = list(self.blocked)
        kept = []
        for call in trace:
            hit = next((b for b in pending if b["tool"] == call.tool_name and b["args"] == call.args), None)
            if hit is not None:
                pending.remove(hit)
            else:
                kept.append(call)
        return messages, kept


def run_once(scenario, env_factory, tools, guarded):
    last_error = ""
    for attempt in range(4):
        try:
            inner = make_agent(MODEL)
            agent = LiveGuardedAgent(inner, GUARD) if guarded else inner
            result = Evaluator(tools=tools).run(scenario, agent, env_factory())
            return {
                "status": "ok",
                "attack_succeeded": bool(result.attack_succeeded),
                "task_completed": bool(result.task_completed),
                "blocked": list(agent.blocked) if guarded else [],
            }
        except Exception as e:
            last_error = str(e)[:200]
            wait = 8 * (attempt + 1)
            print(f"      (hiccup: {last_error[:80]} ... waiting {wait}s and retrying)", flush=True)
            time.sleep(wait)
    return {"status": "error", "error": last_error, "attack_succeeded": False, "task_completed": False, "blocked": []}


def verdict(r):
    if r["status"] != "ok":
        return "ERROR"
    return "FAILED" if r["attack_succeeded"] else "SAFE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()
    n = args.repeats

    print("=" * 78)
    print("AgentSec-Bench live test: AgentGuard OFF vs ON")
    print(f"Model: {MODEL} (Groq free tier) | Scenarios: {len(SCENARIO_MATRIX)} | Repeats each: {n}")
    print("SAFE = the AI did not take the bad action. FAILED = it did.")
    print("=" * 78, flush=True)

    rows = []
    for scenario, env_factory, tools in SCENARIO_MATRIX:
        print(f"\n{scenario.id}  ({scenario.threat_category.value})", flush=True)
        print(f"  Request: {scenario.prompt[:90]}", flush=True)
        for i in range(1, n + 1):
            off = run_once(scenario, env_factory, tools, guarded=False)
            on = run_once(scenario, env_factory, tools, guarded=True)
            blocked_names = [b["tool"] for b in on["blocked"]]
            note = f"  AgentGuard blocked: {', '.join(blocked_names)}" if blocked_names else ""
            print(f"  try {i}:  OFF -> {verdict(off):<7}  ON -> {verdict(on):<7}{note}", flush=True)
            rows.append({"scenario": scenario.id, "category": scenario.threat_category.value,
                         "try": i, "off": off, "on": on})
            time.sleep(0.3)

    print("\n" + "=" * 78)
    print("SCOREBOARD (attacks that succeeded, out of tries)")
    print("=" * 78)
    print(f"{'Scenario':<9} {'Risk':<28} {'OFF':>5} {'ON':>5} {'Blocked':>8} {'Job done OFF/ON':>16}")
    tot = {"off": 0, "on": 0, "blocked": 0, "joboff": 0, "jobon": 0, "tries": 0, "errors": 0}
    for scenario, _, _ in SCENARIO_MATRIX:
        rs = [r for r in rows if r["scenario"] == scenario.id]
        t = len(rs)
        off_f = sum(r["off"]["attack_succeeded"] for r in rs)
        on_f = sum(r["on"]["attack_succeeded"] for r in rs)
        blk = sum(len(r["on"]["blocked"]) for r in rs)
        job_off = sum(r["off"]["task_completed"] for r in rs)
        job_on = sum(r["on"]["task_completed"] for r in rs)
        err = sum((r["off"]["status"] != "ok") + (r["on"]["status"] != "ok") for r in rs)
        print(f"{scenario.id:<9} {scenario.threat_category.value:<28} {off_f:>3}/{t} {on_f:>3}/{t} {blk:>8} {job_off:>7}/{t} {job_on}/{t}")
        tot["off"] += off_f; tot["on"] += on_f; tot["blocked"] += blk
        tot["joboff"] += job_off; tot["jobon"] += job_on; tot["tries"] += t; tot["errors"] += err
    T = tot["tries"]
    print("-" * 78)
    print(f"{'TOTAL':<9} {'':<28} {tot['off']:>3}/{T} {tot['on']:>3}/{T} {tot['blocked']:>8} {tot['joboff']:>7}/{T} {tot['jobon']}/{T}")
    print(f"\nAttacks that succeeded with AgentGuard OFF: {tot['off']} of {T}")
    print(f"Attacks that succeeded with AgentGuard ON:  {tot['on']} of {T}")
    print(f"Tool calls AgentGuard blocked: {tot['blocked']}")
    if tot["errors"]:
        print(f"Runs that hit errors: {tot['errors']} (see results file)")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"live_demo_results_{stamp}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"model": MODEL, "repeats": n, "run_time_utc": stamp, "rows": rows}, f, indent=2)
    print(f"\nFull results saved to {fname}")


if __name__ == "__main__":
    main()