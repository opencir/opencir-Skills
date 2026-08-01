# Security Investigation Skills

End-to-end investigation skills — the ones that take an analyst from "something
looks wrong" through evidence collection, enrichment, timeline, and root cause to a
written deliverable.

These are distinct from the detection skills in [`../skills/`](../skills/), which
answer *"is this happening?"*. The skills here answer *"what happened, how far did it
go, why, and what do we do about it?"*

## Skills in this collection

| Skill | Domain | What it produces |
|---|---|---|
| [`investigating-business-email-compromise`](investigating-business-email-compromise/) | `incident-response` | Seven-section self-contained HTML incident report for a Microsoft 365 / Entra ID BEC case |

## Conventions

Skills here follow the same contract as those in `../skills/`:

- A `SKILL.md` with the required frontmatter (`name`, `description`, `domain`,
  `subdomain`, `tags`, `version`, `author`, `license`)
- Optional `references/`, `scripts/`, and `assets/` subdirectories
- An Apache-2.0 `LICENSE`
- Registration in the repository's root [`index.json`](../index.json), with the
  `path` prefixed by this folder name

Validate a skill here the same way as anywhere else in the repo:

```bash
python3 tools/validate-skill.py "Security investigation skills/<skill-name>/"
python3 tools/validate-skill.py --all
```

`--all` covers this folder because it is listed in `SKILL_ROOTS` in
[`tools/validate-skill.py`](../tools/validate-skill.py). If you add another
collection folder, add it there too so the validator keeps finding everything.

## Scope

As everywhere in this repository, skills must be defensive, analytical, or
educational. Investigation skills read real user activity and personal data, so each
one carries an authorized-use notice covering evidence handling, data minimisation,
and distribution of the resulting report. See [`../CONTRIBUTING.md`](../CONTRIBUTING.md).
