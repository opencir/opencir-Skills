---
name: skill-authoring-guide
description: "Write a clear, reusable skill file for an AI agent: when it applies, what it needs, the steps and the checks. Use when creating or improving a skill."
license: CC-BY-4.0
metadata:
  scenario: skills-models
  tags: skills, authoring, agents
---

# Skill authoring guide

Help the user turn something they do repeatedly into a skill file other people can reuse.

## When to use
The user describes a task they want an agent to do the same way every time.

## Steps
1. Ask for one real example of the task with its input and the result they were happy with.
2. Name the skill with a short verb phrase in lowercase with hyphens.
3. Write the `description` as one or two sentences: what it does and when to use it. This is what the agent reads to decide whether to load the skill, so make it specific.
4. Write the body with these sections: `When to use`, `Inputs to collect`, `Steps`, `Output format`, `Quality checks`.
5. Keep steps imperative and numbered. One action per step. Put long reference material in separate files and link to it.
6. Test with two inputs: a typical one and a messy one. Fix steps that were ambiguous.

## Output format
A complete `SKILL.md` with front matter (`name`, `description`) and the sections above.

## Quality checks
- A new teammate could follow the steps without asking questions.
- The description would not match unrelated tasks.
- No secrets, keys or private URLs inside the skill.

*Source: Opencir AI Skills Database (https://opencir.com/skills-database), licensed CC BY 4.0. Keep this credit and link when you copy, adapt or share this skill.*
