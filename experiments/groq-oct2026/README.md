# Groq free-tier tests, October 2026

Archive of early pilot and demo runs made on the groq-free-tier-pilot branch (commit 03d7312, tag v0.2-paper1). These files are kept as a record of what was run. They have not been re-run or tested from this folder location.

## Contents

Groq pilot results, 2026-10-03
- groq_pilot_results.json and groq_pilot_results_v2.json: 9 results each. Provider recorded as the Groq free tier, model openai/gpt-oss-20b. The v2 file is tagged harness_version multi-turn-fix, which corresponds to the multi-turn tool execution loop added on this branch.

Live demo runs, 2026-10-06
- run_live_demo.py: the demo script. It imports the agentsec_bench package and scripts/run_comparison.py and scripts/experiment_week3.py from this repository.
- live_demo_results_20261006_133652.json, _134926.json, _141353.json, _142752.json: outputs of four runs with model openai/gpt-oss-20b, using 1, 2, 2 and 2 repeats (9 rows per repeat). The files do not record the provider.
- patch_case.py: a small helper script edited during the same session.

Evidence and transcripts, 2026-10-06
- make_transcripts.py (imports scripts/run_comparison.py) and evidence_transcripts.txt.
- evidence_pack/: run1_results.json, run2_results.json and run3_transcript.txt. The zip copy of this folder is not included.

## Notes

- All scenarios are synthetic and run in a simulated sandbox.
- The files were scanned before being added: no API-key-like strings and no local file paths were found.
- Scripts may expect to be run from the repository root; this has not been checked.