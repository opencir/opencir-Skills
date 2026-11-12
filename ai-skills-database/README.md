# AI Skills Database

Reusable skills for AI agents, organized by the scenario they are used in. Each skill is one folder with a `SKILL.md` file: a short description the agent reads to decide when to load it, then the steps, the output format and the quality checks.

All skills in this repository are original work written for this project, licensed CC BY 4.0 (credit and link required, see [License](#license)).

## Scenarios

| Scenario | Skill |
| --- | --- |
| `agent-workflows` | [workflow-planner](skills/agent-workflows/workflow-planner/SKILL.md) |
| `agent-support` | [support-agent-playbook](skills/agent-support/support-agent-playbook/SKILL.md) |
| `sales-growth` | [lead-research-brief](skills/sales-growth/lead-research-brief/SKILL.md) |
| `data-analytics` | [question-to-analysis](skills/data-analytics/question-to-analysis/SKILL.md) |
| `social-analysis` | [social-listening-report](skills/social-analysis/social-listening-report/SKILL.md) |
| `content-creation` | [brand-voice-article](skills/content-creation/brand-voice-article/SKILL.md) |
| `digital-human` | [digital-presenter-script](skills/digital-human/digital-presenter-script/SKILL.md) |
| `cyber-intel` | [ioc-triage-note](skills/cyber-intel/ioc-triage-note/SKILL.md) |
| `governance` | [ai-output-review](skills/governance/ai-output-review/SKILL.md) |
| `knowledge` | [meeting-to-knowledge](skills/knowledge/meeting-to-knowledge/SKILL.md) |
| `skills-models` | [skill-authoring-guide](skills/skills-models/skill-authoring-guide/SKILL.md) |
| `training` | [lesson-plan-builder](skills/training/lesson-plan-builder/SKILL.md) |

## Use a skill

Copy the skill's folder into your agent's skills directory (for example `.claude/skills/<name>/`), or paste the contents of `SKILL.md` into the agent's instructions. The website lists the same skills with a copy button.

## Layout

```
skills/<scenario>/<skill-name>/SKILL.md   one skill
scenarios.json                            scenario ids and the website solution each belongs to
scripts/build-catalog.mjs                 validates every skill and writes catalog.json
catalog.json                              generated index used by the website
```

## Check and build

```
node scripts/build-catalog.mjs
```

This fails if a skill has no front matter, a `name` that differs from its folder, a missing `description`, a scenario that is not in `scenarios.json`, or lacks the `When to use`, `Steps` and `Quality checks` sections. Run it from this folder’s parent with `node ai-skills-database/scripts/build-catalog.mjs`, or from inside the folder with `node scripts/build-catalog.mjs`.

## License

Licensed under **CC BY 4.0**: free to use, adapt and share, including commercially, but you must credit the **Opencir AI Skills Database** and link to https://opencir.com/skills-database. Each skill ends with the credit line to keep. See [LICENSE.md](LICENSE.md).
