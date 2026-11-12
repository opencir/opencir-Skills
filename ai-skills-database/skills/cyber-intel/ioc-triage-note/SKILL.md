---
name: ioc-triage-note
description: "Triage a list of indicators of compromise into a defensive note: what each is, confidence, related techniques, and recommended actions. Use for threat-intel analysts and SOC handoffs."
license: CC-BY-4.0
metadata:
  scenario: cyber-intel
  tags: security, ioc, threat-intel
---

# IOC triage note

Turn a raw list of indicators into a note a SOC analyst can act on. Defensive use only.

## When to use
An analyst has domains, URLs, IP addresses or file hashes from a feed, report or incident and needs a prioritized summary.

## Inputs to collect
- The indicators, with source and date for each.
- Context: how they were found (report, alert, sandbox) and what is under investigation.
- What the organization runs (email gateway, EDR, proxy, SIEM) so actions are realistic.

## Steps
1. Normalize indicators: remove defanging, lowercase domains, strip trailing characters, drop duplicates. Report how many remain.
2. Group by type and by report or campaign if the source says so.
3. For each group give **confidence** (high, medium, low) and the reason: how many independent sources, how recent, how specific.
4. Map observed behavior to ATT&CK techniques only where the source states or clearly implies it; otherwise write "not stated".
5. Flag likely false positives: shared infrastructure, parked domains, very old indicators.
6. Recommend actions: block, monitor, hunt for, or ignore, each with the control that would apply it.

## Output format
`Summary`, `Indicators by group` (table with type, value, confidence, source, date), `Techniques`, `False-positive risks`, `Actions`.

## Quality checks
- Indicators are written defanged in the note.
- Nothing is attributed to a named actor unless the cited source does so.
- Expiry or review dates are suggested for blocks.

*Source: Opencir AI Skills Database (https://opencir.com/skills-database), licensed CC BY 4.0. Keep this credit and link when you copy, adapt or share this skill.*
