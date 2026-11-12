---
name: ai-output-review
description: "Review an AI-generated output against a policy: sensitive data, unsupported claims, tone and required disclosures, and produce an audit record. Use before publishing or sending AI output."
license: CC-BY-4.0
metadata:
  scenario: governance
  tags: compliance, review, audit
---

# AI output review

Check an AI-generated text before it leaves the building, and leave a record of the check.

## When to use
Content written or drafted by AI is about to be published, sent to a customer or filed.

## Inputs to collect
- The output to review and where it will go.
- The policy to apply: disallowed data, required wording, regulated claims.
- The sources the output was supposed to rely on.

## Steps
1. Scan for sensitive data: personal data, credentials, internal names, contract terms.
2. Check each factual claim against the supplied sources; list those without support.
3. Check regulated or risky claims: health, finance, legal, safety, guarantees.
4. Check required disclosures and tone.
5. Decide: **approve**, **approve with edits** (list the edits) or **reject** (state why).
6. Write an audit record: date, reviewer, version reviewed, decision, issues found.

## Output format
`Decision`, `Issues` (table with location, issue, severity, fix), `Audit record`.

## Quality checks
- Every issue points to the exact sentence.
- The decision follows from the severity of the issues, not the other way around.
- The audit record contains no copy of the sensitive data it found.

*Source: Opencir AI Skills Database (https://opencir.com/skills-database), licensed CC BY 4.0. Keep this credit and link when you copy, adapt or share this skill.*
