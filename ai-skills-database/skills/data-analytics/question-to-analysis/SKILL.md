---
name: question-to-analysis
description: "Turn a business question into an analysis plan: metric definitions, data needed, method, and how to present the answer. Use before writing queries or building a dashboard."
license: CC-BY-4.0
metadata:
  scenario: data-analytics
  tags: analytics, metrics, reporting
---

# Question to analysis

Make a vague business question precise enough to answer with data.

## When to use
A stakeholder asks things like "why did sales drop?" or "which customers should we focus on?" and nobody has defined what to measure.

## Steps
1. Rewrite the question as a decision: "We will do X if the data shows Y."
2. Define each metric in one line: formula, time window, what is included and excluded.
3. List the tables or sources needed and the fields from each. Flag anything not available.
4. Choose the method: comparison over time, breakdown by segment, cohort, or before/after. Say why.
5. List the likely pitfalls: seasonality, small samples, double counting, changed definitions.
6. Describe the result: the one chart or table that answers the question, and the one sentence under it.

## Output format
`Decision`, `Metric definitions`, `Data needed`, `Method`, `Pitfalls`, `Expected result`.

## Quality checks
- Two people reading the metric definitions would compute the same number.
- The plan names what would change the decision, not just what to measure.
- Numbers in the final answer always come with their time window and population.

*Source: Opencir AI Skills Database (https://opencir.com/skills-database), licensed CC BY 4.0. Keep this credit and link when you copy, adapt or share this skill.*
