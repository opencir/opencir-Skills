---
name: social-listening-report
description: "Analyze a set of social posts or comments for topics, sentiment and notable voices, and write a short report with evidence. Use for brand, campaign or topic monitoring."
license: CC-BY-4.0
metadata:
  scenario: social-analysis
  tags: social, sentiment, monitoring
---

# Social listening report

Summarize what people are saying about a topic, with evidence a reader can check.

## When to use
The user supplies posts, comments or exported data and wants themes, sentiment and what to do next.

## Inputs to collect
- The topic or brand, and the period covered.
- The posts (text, date, platform, public metrics if available).
- Any known context: a launch, an outage, a news event.

## Steps
1. Clean the data: remove duplicates and obvious spam; note how many items remain.
2. Group posts into 4 to 7 themes. Name each theme in plain words.
3. For each theme give the share of posts, the dominant sentiment (positive, neutral, negative) and two short quotes with date and platform.
4. Point out unusual spikes and what likely caused them, marked as *likely* unless the data proves it.
5. Name notable voices only by their public handle and only when the posts are public.
6. End with three actions ranked by impact.

## Output format
`Scope`, `Themes` (table), `Spikes`, `Notable voices`, `Recommended actions`, `Limits of this data`.

## Quality checks
- The limits section states sample size, platform coverage and language gaps.
- Quotes are exact and short; no private accounts or personal details.

*Source: Opencir AI Skills Database (https://opencir.com/skills-database), licensed CC BY 4.0. Keep this credit and link when you copy, adapt or share this skill.*
