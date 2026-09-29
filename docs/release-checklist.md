# v0.1.0 Release Checklist (Week 1)

Steps that need a human on the actual GitHub/Zenodo accounts - not something
that can be done through a file edit. Everything else on the Week 1 checklist
is already committed (SECURITY.md, CONTRIBUTING.md, CITATION.cff, docs/, the
architecture diagram, the dataset export).

## 1. Cut the actual GitHub Release

The `v0.1.0-baseline` git tag already exists, but no GitHub Release has been
published from it yet (a Release is a separate GitHub object, not just a tag).

1. Go to `https://github.com/samyshyaka/agentsec-bench/releases/new`
2. Choose the existing tag `v0.1.0-baseline` (or cut a fresh `v0.1.0` tag once
   all of Week 1's other items are merged into `staging`/`main` - your call).
3. Title: `AgentSec-Bench v0.1.0`
4. Description (draft - edit freely):

   > First versioned release of AgentSec-Bench: a reproducible security
   > evaluation framework for tool-using AI agents, extending beyond
   > AgentDojo's prompt-injection focus into authorization, tool misuse,
   > privilege escalation, and data exfiltration.
   >
   > - 9 scenarios across 8 threat categories (see `docs/threat-model.md`)
   > - Two independent detection mechanisms: role-based and destination-based
   > - Full test suite, reproducibility instructions, Docker support
   > - Versioned dataset export: `dataset/agentsec-bench-v0.1.0-dataset.json`
   > - See `docs/benchmark-card.md` and `docs/limitations.md` for intended
   >   use, scope, and known gaps.
5. Attach `dataset/agentsec-bench-v0.1.0-dataset.json` as a release asset
   (drag it into the release form) so the dataset is directly downloadable
   from the Release page, not just present in the repo.
6. Publish.

## 2. Mint a Zenodo DOI

1. Go to `https://zenodo.org` and log in (or create an account) with the
   account that should be listed as the archiving owner.
2. Go to GitHub integration settings: `https://zenodo.org/account/settings/github/`
3. Find `samyshyaka/agentsec-bench` in the repository list and flip it on.
   (If it's not listed, you may need to be logged in as an account with
   admin access to the repo, or use the GitHub App flow Zenodo now
   recommends instead of the legacy OAuth flow - check Zenodo's current
   docs, this has changed over time.)
4. Once enabled, cutting a **new** GitHub Release (or the one from step 1,
   if done after enabling this) triggers Zenodo to automatically archive it
   and mint a DOI.
5. Copy the minted DOI back into `CITATION.cff` (add a `doi:` field) and into
   `README.md`, and update `CITATION.cff`'s `date-released` to match the
   actual Release date.

## 3. After both are done

- Update `CITATION.cff`'s `date-released` field (currently set to the git
  tag's commit date, `2026-09-23`, with a note that it should be updated
  once a real Release exists).
- Confirm with Samy whether he (or anyone else) should be added to
  `CITATION.cff`'s `authors` list before the DOI is minted - the DOI will
  point to whatever's in that file at release time.
