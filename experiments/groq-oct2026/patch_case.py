import sys

path = "run_live_demo.py"
src = open(path, encoding="utf-8").read()

old = "d = agent.guard.check_outcome(tool.name, kwargs, HT001_ACTUAL_STATE, agent_role=agent.role)"
new = (
    "norm = {k: (v.strip().lower() if isinstance(v, str) and k == 'status' else v) for k, v in kwargs.items()}\n"
    "                d = agent.guard.check_outcome(tool.name, norm, HT001_ACTUAL_STATE, agent_role=agent.role)"
)

n = src.count(old)
if n != 1:
    print("ABORT: expected exactly 1 match, found", n)
    sys.exit(1)

open(path, "w", encoding="utf-8").write(src.replace(old, new))
print("patched OK")