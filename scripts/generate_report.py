import json
from datetime import datetime

with open("results.json") as f:
    data = json.load(f)

results = data["results"]
run_timestamp = data["run_timestamp"]

total = len(results)
attacks_caught = sum(1 for r in results if r["attack_succeeded"] and (r["unauthorized_tool_calls"] or r["suspicious_destinations"]))
attacks_attempted = sum(1 for r in results if r["attack_succeeded"])
attacks_missed = attacks_attempted - attacks_caught

rows_html = ""
for r in results:
    if r["attack_succeeded"] is None:
        status = "N/A"
        status_class = "neutral"
    elif r["attack_succeeded"]:
        caught = bool(r["unauthorized_tool_calls"] or r["suspicious_destinations"])
        status = "ATTACK CAUGHT" if caught else "ATTACK MISSED"
        status_class = "caught" if caught else "missed"
    else:
        status = "CLEAN"
        status_class = "clean"

    flags = []
    if r["unauthorized_tool_calls"]:
        flags.append(f"Role violation: {', '.join(r['unauthorized_tool_calls'])}")
    if r["suspicious_destinations"]:
        dests = ", ".join(d["destination"] for d in r["suspicious_destinations"])
        flags.append(f"Suspicious destination: {dests}")
    flags_text = "<br>".join(flags) if flags else "-"

    rows_html += f"""
    <tr class="{status_class}">
        <td>{r['scenario']}</td>
        <td>{r['category']}</td>
        <td>{r['owasp_control_id'] or '-'}</td>
        <td>{r['agent']}</td>
        <td><span class="badge {status_class}">{status}</span></td>
        <td>{flags_text}</td>
    </tr>
    """

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AgentSec-Bench Results</title>
<style>
    body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 40px; background: #f7f7f8; color: #1a1a1a; }}
    h1 {{ font-size: 22px; margin-bottom: 4px; }}
    .meta {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
    .summary {{ display: flex; gap: 16px; margin-bottom: 28px; }}
    .stat {{ background: white; border-radius: 8px; padding: 16px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    .stat .num {{ font-size: 26px; font-weight: 700; }}
    .stat .label {{ font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.03em; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    th {{ text-align: left; background: #1a1a1a; color: white; padding: 10px 12px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.03em; }}
    td {{ padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #eee; vertical-align: top; }}
    .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
    .badge.caught {{ background: #e6f4ea; color: #1e7e34; }}
    .badge.clean {{ background: #e6f4ea; color: #1e7e34; }}
    .badge.missed {{ background: #fdecea; color: #b3261e; }}
    .badge.neutral {{ background: #eee; color: #555; }}
    tr.missed {{ background: #fff8f7; }}
</style>
</head>
<body>
    <h1>AgentSec-Bench Results</h1>
    <div class="meta">Run: {run_timestamp}</div>

    <div class="summary">
        <div class="stat"><div class="num">{total}</div><div class="label">Test Runs</div></div>
        <div class="stat"><div class="num">{attacks_attempted}</div><div class="label">Attacks Attempted</div></div>
        <div class="stat"><div class="num">{attacks_caught}</div><div class="label">Attacks Caught</div></div>
        <div class="stat"><div class="num">{attacks_missed}</div><div class="label">Attacks Missed</div></div>
    </div>

    <table>
        <tr>
            <th>Scenario</th>
            <th>Category</th>
            <th>OWASP</th>
            <th>Agent</th>
            <th>Result</th>
            <th>Detection Detail</th>
        </tr>
        {rows_html}
    </table>
</body>
</html>
"""

with open("report.html", "w", encoding="utf-8") as f:
    f.write(html)

print(f"Report written to report.html ({total} rows, {attacks_caught}/{attacks_attempted} attacks caught)")