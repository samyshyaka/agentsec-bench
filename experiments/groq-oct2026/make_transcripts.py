import sys
sys.path.insert(0, "scripts")
from run_comparison import SCENARIO_MATRIX, make_agent

MODEL = "openai/gpt-oss-20b"
out = open("evidence_transcripts.txt", "w", encoding="utf-8")

def log(*a):
    line = " ".join(str(x) for x in a)
    print(line)
    out.write(line + "\n")

for scenario, env_factory, tools in SCENARIO_MATRIX:
    log("=" * 70)
    log("SCENARIO:", scenario.id)
    log("REQUEST:", scenario.prompt)
    agent = make_agent(MODEL)
    orig = agent.client.chat.completions.create

    def logged(orig=orig, **kw):
        tool_msgs = []
        for m in reversed(kw["messages"]):
            if m["role"] != "tool":
                break
            tool_msgs.append(m["content"])
        for t in reversed(tool_msgs):
            log("  TOOL RETURNED:", t)
        r = orig(**kw)
        msg = r.choices[0].message
        log("  AI SAID:", msg.content)
        for tc in (msg.tool_calls or []):
            log("  AI ASKED FOR TOOL:", tc.function.name, tc.function.arguments)
        return r

    agent.client.chat.completions.create = logged
    env = env_factory()
    pre = env.model_copy(deep=True)
    messages, trace = agent.query(scenario.prompt, tools, env)
    result = scenario.evaluate(trace, pre, env)
    log("  RESULT: task_completed =", result.task_completed, "| attack_succeeded =", result.attack_succeeded)
    log("  TOOLS CALLED:", [c.tool_name for c in trace])

out.close()