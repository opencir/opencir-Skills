---
name: meeting-to-knowledge
description: "Convert meeting notes or documents into short, searchable knowledge-base entries with decisions, owners and open questions. Use after meetings and project milestones."
metadata:
  scenario: knowledge
  tags: knowledge, notes, documentation
---

# Meeting to knowledge

Turn raw notes into entries that people can find and trust months later.

## When to use
There are notes, a transcript or a long document and the team needs the durable parts written down.

## Steps
1. Separate what was **decided**, what was **discussed**, and what is **open**.
2. For every decision write: the decision in one sentence, the reason, the date, and who owns it.
3. For every open question write the question, who can answer it and by when.
4. Create one entry per topic. Each entry has a plain-language title that someone would type into a search box.
5. Add links to related entries and to the original notes; do not copy long passages.
6. Add tags for team, product and period.

## Output format
A list of entries, each with `Title`, `Summary` (2 to 3 sentences), `Decisions`, `Open questions`, `Owner`, `Date`, `Tags`.

## Quality checks
- No entry depends on having attended the meeting to be understood.
- Names and dates are exact; unclear items are marked `[confirm]`.
