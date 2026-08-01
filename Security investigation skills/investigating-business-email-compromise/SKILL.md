---
name: investigating-business-email-compromise
description: Run an end-to-end Business Email Compromise investigation in Microsoft
  365 and Entra ID — intake the case, compare the user's legitimate ASN/ISP/geo/device
  baseline against observed sign-ins, enrich IOCs through a threat intelligence MCP
  server, quantify SharePoint and OneDrive exfiltration, review Microsoft Graph API
  abuse, reconstruct a UTC timeline, determine root cause, and generate a self-contained
  HTML incident report. Activates for requests involving BEC investigation, email
  account compromise, account takeover analysis, or producing a BEC incident report.
domain: cybersecurity
subdomain: incident-response
tags:
- bec
- incident-response
- microsoft-365
- entra-id
- account-takeover
- unified-audit-log
- microsoft-graph
- threat-intelligence
- html-report
- dfir
version: '1.0'
author: opencir
license: Apache-2.0
mitre_attack:
- T1566.002
- T1078.004
- T1114.002
- T1114.003
- T1098.002
- T1530
- T1213.002
- T1657
- T1562.001
- T1550.001
- T1110.003
- T1136.003
nist_csf:
- DE.AE-02
- DE.CM-01
- RS.MA-01
- RS.AN-03
- RS.CO-02
- RC.RP-01
d3fend_techniques:
- Message Analysis
- User Behavior Analysis
- Authentication Event Thresholding
- Session Duration Analysis
- Domain Name Reputation Analysis
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - stealth
  - positioning
  - monetization
  techniques:
  - id: T1660
    name: Phishing
    tactic: initial-access
    source: attack
  - id: F1005.006
    name: 'Account Manipulation: Change of Payment Details'
    tactic: positioning
    source: f3
  - id: F1022
    name: Delete Relevant Emails
    tactic: stealth
    source: f3
  - id: F1025.003
    name: 'Electronic Funds Transfer: Wire Transfer'
    tactic: monetization
    source: f3
---
# Investigating Business Email Compromise

> **Authorized-use-only notice:** This investigation reads a named individual's mailbox
> contents, file access history, and sign-in locations. Run it only on accounts you are
> authorized to investigate, under an open case reference. Mailbox and file activity are
> personal data in most jurisdictions — apply your organisation's evidence-handling, data
> minimisation, and retention rules, involve HR/Legal where your policy requires it, and
> restrict distribution of the generated report. The report defangs IOCs so it can be
> circulated safely, but it still contains the subject's identity and activity.

## Overview

Business Email Compromise investigations fail most often not because the evidence is
missing, but because it is scattered: sign-in telemetry lives in Entra ID, mail access in
the Unified Audit Log, file theft in SharePoint and OneDrive audit records, and
persistence in Microsoft Graph consent grants. Each source answers a fragment of the
question, and the analyst is left stitching them together by hand under time pressure.

This skill unifies that work into one pass. It collects the case facts up front, including
the **legitimate baseline** for the user — their normal ASN, ISP, country, city, device
type, OS, and browser — so that every observed value can be judged as a match or a
deviation rather than assessed in isolation. It enriches every IP, domain, and URL through
a threat-intelligence MCP server, quantifies download spikes against the user's own
30-day history, and reconstructs a single UTC timeline across all sources. The output is a
self-contained HTML report with seven sections, ready to attach to the incident ticket.

The investigation is deliberately tolerant of gaps. Any fact the analyst cannot supply is
recorded as `UNKNOWN` and rendered as such — an incomplete report produced during the
incident is more useful than a complete one produced after it.

## When to Use

- When a user reports, or a detection fires on, a suspected compromised Microsoft 365 mailbox
- When you need to determine the scope of an account takeover: what was read, downloaded, or forwarded
- When a phishing email led to a credential or token theft and you must trace what followed
- When anomalous sign-in geography, ASN, or device fingerprint needs to be judged against a user's norm
- When an incident requires a written BEC report with timeline, root cause, and recommendations
- When you need to enrich sign-in IPs and phishing URLs against threat intelligence during triage

**Do not use** this skill to monitor an employee outside an authorised investigation, or as
a substitute for a formal forensic acquisition where litigation or law enforcement referral
is anticipated — audit-log review is not a forensically sound image.

## Prerequisites

- Microsoft 365 with **Unified Audit Log enabled** (`Search-UnifiedAuditLog` returns data);
  note UAL retention is 180 days on E5/Audit Premium, 90 days on E3
- Entra ID sign-in log access — 30-day retention in the portal, longer if exported to a
  Log Analytics workspace (`SigninLogs`, `MicrosoftGraphActivityLogs` tables)
- Roles: **Security Reader** minimum for review; **Global Reader + Audit Logs role** for full
  UAL access. Containment actions additionally need Exchange/Entra admin rights
- `MailItemsAccessed` auditing enabled (E5 / Microsoft Purview Audit Premium) — without it,
  "what did they read" cannot be answered from logs
- Microsoft Defender for Cloud Apps (MDCA), optional — enables the `CloudAppEvents` advanced
  hunting queries in `references/workflows.md` for inbox-rule detection and 60-day ISP/
  country/user-agent baselining; the UAL/Sentinel path in Step 2–4 works without it
- A threat-intelligence MCP server connected to the agent — this skill targets the
  [Opencir Threat Intelligence MPC](https://github.com/opencir/Opencir-Threat-Intelligence-MPC)
  server. Without it, enrichment falls back to manual API lookups (see `references/api-reference.md`)
- Python 3.8+ to run the report generator (standard library only, no packages to install)
- The user's **legitimate baseline** — their normal work location, ISP, and corporate device
  build. Sourced from the analyst, the user's manager, or IT asset inventory
- Bulk UAL export tooling, optional but recommended at scale — the Security & Compliance
  Center UI caps at 5,000/50,000 records and `Get-MessageTrace` only covers the last 7–10
  days without paging. See "Bulk collection tools" in Tools & Systems below.

## MITRE ATT&CK Mapping

| Technique | Name | Why it applies to a BEC investigation |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | The initial-access vector this skill traces backwards to |
| T1078.004 | Valid Accounts: Cloud Accounts | Attacker signs in with stolen credentials or a replayed token |
| T1114.002 | Email Collection: Remote Email Collection | `MailItemsAccessed` reveals which mail was read |
| T1114.003 | Email Collection: Email Forwarding Rule | Inbox rules are the most common BEC persistence and concealment mechanism |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Delegate/mailbox permissions survive a password reset |
| T1530 | Data from Cloud Storage Object | OneDrive/SharePoint mass download is the exfiltration event |
| T1213.002 | Data from Information Repositories: SharePoint | File *views* indicate reconnaissance even without download |
| T1657 | Financial Theft | The BEC objective — payment redirection or invoice fraud |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Attacker disables the Audit Log or purges evidence to defeat this investigation |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | OAuth app tokens bypass MFA and outlive a password reset |
| T1110.003 | Brute Force: Password Spraying | Low-and-slow credential attempts precede many BEC sign-ins |
| T1136.003 | Create Account: Cloud Account | Attacker creates a new cloud account to maintain access independent of the victim's |

## Workflow

BEC investigations begin with a stakeholder question, not a step number. Use this map —
adapted from PwC's *Business Email Compromise Guide* — to jump to the step that answers it;
most questions need more than one:

| Question | Answered in |
|---|---|
| What accounts were compromised or accessed? | Steps 3–4 |
| Is the threat actor still in the environment? | Steps 3, 7, 8 |
| When did the intrusion begin? | Steps 4, 9 |
| How long did the threat actor maintain access? | Steps 3, 4, 7, 8, 9 |
| What data was accessed or exfiltrated? | Step 6 |
| Is there someone internal involved? | Steps 4, 10 |
| Is this targeted, and who is responsible? | Step 5, `references/standards.md` attribution section |
| How do we prevent recurrence? | Steps 10–11 |

### Step 1: Open the case and capture intake

Copy `assets/case-template.json` to a working file, then ask the analyst for each field
below. Record anything unavailable as the literal string `UNKNOWN` — never block on a
missing answer, and never guess a value.

```
Case          : title, investigation ID, analyst, date (UTC), severity
Asset         : username / UPN, display name, department, role, VIP flag
Legitimate    : ASN, ISP, country, city, device type (laptop|desktop), OS, browser + version
Observed      : IP(s), ASN, ISP, country, city, device type, OS, browser + version
Phishing email: sender, subject, URL, received time (UTC), recipient count
```

The **legitimate** block is what makes the report readable. "Sign-in from AS9009 M247,
Bucharest" means little on its own; "sign-in from AS9009 M247, Bucharest — user normally
AS7922 Comcast, Denver, on a corporate Windows 11 laptop" is a finding. Ask for it
explicitly; do not infer a baseline from the same logs you are investigating.

### Step 2: Collect the evidence

Run the queries in `references/workflows.md`. Scope every query to the same window — from
at least 7 days before the phishing email through to the present — so the timeline has a
consistent span. Collect, in order:

1. Entra ID sign-in logs for the user (interactive and non-interactive)
2. Unified Audit Log — mailbox rules and permissions: `UserLoggedIn`, `New-InboxRule`,
   `Set-InboxRule`, `New-TransportRule`, `Set-TransportRule`, `Add-MailboxPermission`,
   `Add-RecipientPermission`, `Add-MailboxFolderPermission`, `Set-MailboxFolderPermission`,
   `Added user`, `Add member to role`, `Add member to group`
3. `MailItemsAccessed` records for the mailbox
4. SharePoint/OneDrive `FileDownloaded`, `FileAccessed`, `FileSyncDownloadedFull`, `AddedToSecureLink`
5. `MicrosoftGraphActivityLogs` and `Consent to application` / `Add service principal` events

`New-TransportRule`/`Set-TransportRule` are organisation-wide mail-flow rules, not per-mailbox
inbox rules — they need Exchange admin rights to create, so their presence points at a
higher-privilege compromise or an admin account. `Add-RecipientPermission`, `Add-MailboxFolderPermission`,
and `Set-MailboxFolderPermission` are less common than `Add-MailboxPermission` but grant the
same practical access (SendAs, folder-level read) and are worth the same scrutiny.
`Added user` and `Add member to role`/`group` catch an attacker creating a fallback account
or granting an existing one admin rights — persistence that outlives every mailbox-level
remediation.

Preserve raw exports alongside the case file. The report is a summary; the exports are the
evidence.

### Step 3: Grade the inbox rules — true positive vs false positive

Not every inbox rule is an attacker rule. Grade each rule found in Step 2 against three
parameters before treating it as an incident artefact, following the criteria in
Microsoft's [inbox manipulation rules alert-grading
playbook](https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules):

1. **Keywords.** Check `BodyContainsWords`, `SubjectContainsWords`, and
   `SubjectOrBodyContainsWords`. Terms like "invoice", "payment", "wire", "phish", "spam",
   or "do not reply" are the attacker filtering out the messages that would expose them —
   the same messages that would alert the victim or the security team. A rule with **no
   keyword filter at all**, applied to all incoming mail, is also a suspicious pattern in
   its own right, not just a keyword-filtered one.
2. **Destination.** If the rule pairs `MoveToFolder` with `MarkAsRead`, check whether the
   destination folder relates to the keywords — mail matching "invoice" or "wire" landing
   in **RSS Feeds**, **Conversation History**, **Archive**, or **Deleted Items** and marked
   read is concealment, not filing. A folder unrelated to the keywords is a weaker signal.
3. **Delete-all.** A rule that deletes **all** incoming mail with no keyword filter is one
   of the strongest single indicators of malicious intent — there is essentially no
   legitimate reason for a user to auto-delete their entire inbox.

Record the grading rationale (keywords found, destination folder, delete-all flag) in each
`mailbox_persistence` entry's `detail` and `assessment` fields — the report should show
*why* a rule was graded TP, not just that it was.

### Step 4: Compare observed activity against the baseline

For each of ASN, ISP, country, city, device type, OS, and browser, mark the observed value
`MATCH`, `DEVIATION`, or `UNKNOWN` against the legitimate baseline. A single deviation is
weak evidence — travel, a new phone, a VPN. The finding is in the **combination**: a new
ASN *and* a new country *and* an unfamiliar user agent arriving within minutes of a normal
sign-in is impossible-travel plus device mismatch, and that is a compromise.

Feed the result into the case file's `baseline_comparison` block. `scripts/agent.py`
computes this automatically:

```bash
python3 scripts/agent.py --case case.json
```

Also check what the user's account was doing **before** the rule was created, and whether
this alert sits inside a larger incident:

- **Prior sign-in activity.** Was the sign-in immediately preceding the rule creation itself
  a deviation (unfamiliar location, ISP, or user agent)?
- **Prior alerts.** Had Entra ID Protection or Defender already raised an alert on this user
  — impossible travel, sign-in from an infrequent country, or multiple failed logins — before
  the rule appeared? A rule created shortly after such an alert is strong corroboration.
- **Related incident.** Check whether this alert has been correlated into an incident with
  other true-positive alerts on the same user or tenant. An inbox-rule alert that stands
  completely alone, with a clean sign-in history and no related alerts, is more likely benign
  user configuration.

If Entra sign-in logs are unavailable (E3 without export) or you need a second source, the
UAL itself carries brute-force and MFA signal: `IdsLocked` (account locked after repeated bad
credentials), `UserKey="Not Available"` (a guessed account that does not exist), and
`UserStrongAuthClientAuthNRequired` / `...RequiredInterrupt` (MFA challenge issued or failed).
A successful login immediately following a burst of these is a compromised account, not
coincidence — but note that a client performing a full mailbox sync can generate a similar
burst of events and is almost always a false positive; check the client/app before calling it
a brute force.

### Step 5: Enrich IOCs through the threat intelligence MCP server

Call the Opencir MPC MCP tools directly. Start with `threatintel_status` to see which
upstream sources are actually configured — the answer changes what the rest of this step
can return, and an unconfigured source must be reported as "not checked", never as "clean".

| Order | Tool | Input | What it establishes |
|---|---|---|---|
| 1 | `threatintel_status` | — | Which sources are live before you rely on them |
| 2 | `threatintel_lookup_ip` | each sign-in IP | Aggregate verdict across AbuseIPDB, OTX, GreyNoise |
| 3 | `greynoise_ip` | each sign-in IP | Mass-scanner noise vs traffic targeted at you |
| 4 | `threatintel_lookup_url` | phishing URL | URLhaus and OTX verdict on the lure |
| 5 | `threatintel_lookup_domain` | sender + URL domain | Domain reputation and hosting history |
| 6 | `feodo_tracker` | — | Whether any sign-in IP appears in active botnet C2 infrastructure |

Where API keys are configured, `abuseipdb_check` returns richer reputation detail and
`otx_search_pulses` links the indicator to named campaigns.

**On ASN attribution:** the MPC server has **no dedicated ASN lookup tool**. ASN and ISP
attribution comes from the `isp` and `usageType` fields AbuseIPDB returns and the metadata
GreyNoise includes, both surfaced inside `threatintel_lookup_ip` — plus whatever the sign-in
log itself recorded. Deciding whether an ASN is *suspicious* is analyst judgement against
the criteria in `references/standards.md`, not a tool call. Record the reasoning in the
case file so the report shows why an ASN was flagged.

### Step 6: Quantify SharePoint and OneDrive exfiltration

Establish the user's normal daily download rate over the preceding 30 days, then compare
the incident window against it. Report the ratio, not just the raw count — "412 files in
90 minutes against a 30-day mean of 6/day" is the finding.

Separate **downloaded** from **viewed**. Files merely viewed still represent exposure and
belong in the report, but they carry different notification obligations than files pulled
down in bulk. Capture file names, sites, and sensitivity labels where present.

Also check `AddedToSecureLink` for documents shared with individuals outside the
organisation — filter out internal recipients and treat any external share created during
the incident window as exfiltration, even if the file was never "downloaded" in the
traditional sense.

### Step 7: Review Microsoft Graph API activity

Look for the persistence that survives a password reset:

- OAuth application consent grants, especially to unverified publishers
- New service principals, or credentials added to an existing one
- Token-based `MicrosoftGraphActivityLogs` calls from the attacker IP or an unfamiliar app ID
- Mail.Read / Mail.ReadWrite / Files.Read.All scopes granted during the incident window

An illicit consent grant means credential reset alone will **not** evict the attacker.
Flag it as a containment blocker in the recommendations.

Then pivot outward from the attacker's IP: search the tenant for any other sign-in, inbox
rule, or Graph activity from the same IP address or, if the ISP itself is uncommon for your
organisation, the same ISP. A single attacker IP is frequently reused against several
mailboxes in the same campaign — finding a second victim here changes the scope of the
whole incident.

### Step 8: Check for evasion and anti-forensics activity

Before trusting the completeness of everything collected so far, check whether the attacker
tried to hide it. Three patterns, drawn from PwC's *Business Email Compromise Guide*:

- **Purge rules.** A rule or manual action that deletes a sent message and its replies lets
  the attacker carry on a fraudulent conversation from the compromised mailbox without the
  real user ever seeing it. Look for delete actions on `Sent Items` alongside the concealment
  rule graded in Step 3, not just on `Inbox`.
- **Audit Log disabled.** `Set-AdminAuditLogConfig` toggling logging off is itself a UAL
  event — search for it explicitly. If found, treat the surrounding time window as a **gap**,
  not as an absence of activity: state in the report that logging was disabled from X to Y
  and that this step cannot rule out attacker action in that window.
- **eDiscovery abuse.** `New-ComplianceSearchAction` with `-Purge`, or an `eDiscovery search
  started or exported` alert, can be used to bulk-delete evidence (e.g. the original phishing
  email) via a legitimate compliance tool. Any such action taken by an account that is not
  part of the legal/eDiscovery team during the incident window is a red flag on its own.

Record findings from this step in `mailbox_persistence` alongside the inbox-rule grading —
each is an artefact with a timestamp, an actor, and an assessment, and belongs in the same
table. An attacker who evades logging is signalling a higher sophistication level; say so in
the executive summary, since it changes how much you should trust "no further activity found"
elsewhere in the case.

### Step 9: Build the unified timeline

Merge every source into one list ordered by UTC timestamp, each entry carrying its source
so the report is auditable. Normalise every timestamp to UTC — mixed local times are the
single most common cause of a wrong BEC narrative.

Then derive the response metrics: dwell time, MTTD, MTTC, MTTR. These belong in the report
whether or not they flatter the response.

### Step 10: Determine root cause

Work backwards from impact to initial access using 5 Whys, recording the evidence behind
each step. Stop at a cause the organisation can actually fix — "user clicked a link" is a
symptom; "no phishing-resistant MFA on a VIP account, and no conditional access policy
blocking legacy authentication" is a root cause. State your confidence and what would raise it.

Before naming an external threat actor, weigh whether the evidence is equally consistent with
a **malicious insider** — an account acting from an expected ASN, on an expected device, with
no MFA anomaly, is one possibility a purely external-attacker narrative will miss. It does not
need to be resolved to close the investigation, but it should be explicitly considered and
ruled in or out with a reason, not silently assumed away.

State confidence using consistent, calibrated language rather than a bare adjective — the UK
Government's probability yardstick works well and keeps confidence comparable across cases:

| Term | Confidence |
|---|---|
| Remote / highly unlikely | < 10% |
| Improbable / unlikely | 10–25% |
| Realistic probability | 26–50% |
| Probable / likely | 51–75% |
| Highly probable / highly likely | 76–90% |
| Almost certain | > 90% |

Attribution to a specific actor or group is usually neither possible nor necessary for
remediation; "financially motivated, opportunistic, consistent with commodity BEC tradecraft"
is often the honest and sufficient answer. See `references/standards.md` for phishing-lure
and infrastructure patterns that support a more specific assessment when the evidence allows it.

### Step 11: Write recommendations

Split into immediate containment, short-term, and long-term. Every recommendation needs an
owner, a priority, and a deadline — the report renders them as an action-item table, and a
row without an owner will not get done.

For a confirmed (TP) inbox rule, the immediate list always includes: disable the malicious
rule, reset the account's credentials, cross-check the risk signal in Entra ID Protection /
Defender for Cloud Apps if licensed, and search the tenant for other accounts touched by the
same attacker IP or ISP (Step 7).

Standard long-term items worth defaulting to unless the organisation already has them: MFA
enforced on every privileged role (not just Global Admin), a NIST-aligned password policy
(references/standards.md), Office 365 logs forwarded to a centralised SIEM, regular scheduled
review of active forwarding/transport rules, external mail forwarding blocked by policy, and
legacy authentication protocols (POP3/IMAP/SMTP AUTH) disabled. For BEC specifically, recommend
a **four-eyes / dual-approval control on bank detail or payment-instruction changes** — the
single non-technical control that stops a successful mailbox compromise from becoming a
successful wire fraud.

### Step 12: Generate the HTML report

```bash
python3 scripts/process.py report --case case.json --out bec-report.html
```

The output is a single self-contained HTML file — no external stylesheets, scripts, or
fonts. It renders offline, prints to PDF, and is safe to attach to a ticket. Validate the
case file first if you have been hand-editing it:

```bash
python3 scripts/process.py validate --case case.json
```

## Key Concepts

| Concept | Description |
|---|---|
| Legitimate baseline | The user's known-good ASN, ISP, geo, device, and browser, supplied by the analyst — the reference every observed value is judged against |
| Deviation stacking | One anomaly is noise; several anomalies within a short window is a compromise signal |
| Impossible travel | Two sign-ins whose geographic separation exceeds any feasible travel speed between them |
| Suspicious ASN | Hosting, VPN, proxy, or bulletproof ASNs appearing where a residential or corporate ASN is expected |
| Download spike ratio | Incident-window download count divided by the user's own 30-day daily mean |
| Illicit consent grant | OAuth permission granted to an attacker-controlled app; survives password reset and must be revoked separately |
| Dwell time | Initial compromise to detection — the headline number for how long the attacker operated undetected |
| Defanging | Rewriting IOCs (`hxxp://`, `1.2.3[.]4`) so a circulated report cannot be clicked into a live threat |
| Inbox rule TP/FP grading | Classifying a rule as malicious by keyword filter, destination folder, and delete-all pattern, per Microsoft's inbox-manipulation-rules playbook — not by the mere existence of a rule |
| Delete-all rule | A rule that deletes or moves **all** incoming mail with no keyword filter — one of the strongest single indicators of a compromised mailbox |
| IP/ISP pivot | Searching the tenant for other accounts touched by the same attacker IP or ISP, to catch a second victim in the same campaign |
| Anti-forensics gap | A window where the attacker disabled audit logging or purged evidence — reported as an evidentiary gap, never mistaken for a quiet period |
| Four-eyes principle | Dual approval required before acting on a bank-detail or payment-instruction change — the control that stops mailbox compromise from becoming wire fraud |
| Estimative language | Calibrated confidence terms (remote, probable, almost certain) mapped to percentage ranges, used for attribution and root-cause confidence statements |

## Tools & Systems

| Tool | Purpose |
|---|---|
| Microsoft Purview Audit (UAL) | `MailItemsAccessed`, inbox rules, file operations, sign-in records |
| Entra ID sign-in logs | IP, ASN, geo, device, user agent, conditional-access result per authentication |
| Log Analytics / Sentinel KQL | Longer retention and joinable queries across `SigninLogs` and `MicrosoftGraphActivityLogs` |
| Microsoft Defender XDR advanced hunting | `CloudAppEvents` for inbox-rule creation and 60-day ISP/country/user-agent baselines, where Defender for Cloud Apps (MDCA) is licensed |
| Exchange Online PowerShell | `Search-UnifiedAuditLog`, `Get-InboxRule`, `Get-MailboxPermission` |
| Opencir Threat Intelligence MPC | MCP server providing IP, domain, URL, and hash enrichment across OTX, AbuseIPDB, GreyNoise, abuse.ch |
| `scripts/agent.py` | Computes baseline deviations and download-spike risk from the case file |
| `scripts/process.py` | Validates the case file and renders the seven-section HTML report |

### Bulk collection tools (optional)

The Security & Compliance Center UI and the Office 365 Management API both cap out well
below what a real BEC case produces — GUI export tops out at 5,000 sorted / 50,000 unsorted
records, and BEC cases commonly run into the millions. These open-source tools, referenced in
PwC's *Business Email Compromise Guide*, page past those limits by paging `Search-UnifiedAuditLog`:

| Tool | Purpose |
|---|---|
| [Office 365 Extractor](https://github.com/PwC-IR/Office-365-Extractor) | Bulk UAL export to CSV, auto-paginating past the 5,000-record session limit; extract the complete UAL or specific RecordTypes |
| [HAWK](https://github.com/Canthv0/hawk) | PowerShell triage tool — pulls sign-in events, inbox rules, forwarding config, and mailbox stats for a single user in one report |
| [MIA (MailItemsAccessed)](https://github.com/PwC-IR/MIA-MailItemsAccessed) | Automates the SessionId → InternetMessageId → Message Trace pivot described in `references/workflows.md` to identify exactly which emails the attacker read |

None of these are required — `Search-UnifiedAuditLog` and the KQL queries in
`references/workflows.md` are sufficient for most cases — but they save significant time once
a case exceeds a few thousand events.

## Common Scenarios

1. **Adversary-in-the-middle token theft** — Sign-in succeeds with MFA satisfied, from a
   hosting ASN in an unexpected country, with a user agent that does not match the user's
   corporate build. The password was never the weakness; the session token was. Password
   reset alone is insufficient — revoke sessions.

2. **Inbox rule concealment** — A rule moving anything matching "invoice", "payment", or
   "wire" to RSS Feeds or Deleted Items, created minutes after first sign-in. Classic BEC
   concealment so the user never sees the fraudulent thread. Maps to T1114.003 and F1022.

3. **Delete-all rule** — A rule with no keyword filter that deletes every incoming message,
   sometimes paired with a forwarding rule that exfiltrates a copy first. Grade as TP on the
   delete-all pattern alone (Step 3); do not wait for a keyword match that will never come.

4. **Mass OneDrive download before extortion** — Hundreds of files pulled in under an hour
   against a baseline of a handful per day. Frequently precedes an extortion demand rather
   than a wire-fraud attempt; scope the data for notification obligations immediately.

5. **Illicit OAuth consent** — No anomalous interactive sign-in at all, because the attacker
   holds an app consent granting `Mail.Read`. Sign-in log review looks clean; the evidence
   is entirely in Graph activity and consent events.

6. **Vendor-thread hijack** — The compromised mailbox is used to reply within a legitimate
   existing invoice thread with altered bank details. Investigation scope must extend to the
   external counterparty, who may not know they are transacting with an attacker.

7. **Evidence tampering** — `Set-AdminAuditLogConfig` disables logging, or a compliance
   search purges the original phishing email, partway through the incident window. Report the
   gap explicitly (Step 8) rather than treating the quiet period as evidence of no activity.

8. **No external anomaly at all** — Sign-in ASN, device, and hours all match the baseline;
   the only artefact is a bank-detail change on an outgoing invoice. Consider a malicious
   insider alongside external compromise (Step 10) rather than assuming account takeover by default.

## Output Format

- **Case file** (`case.json`) — the structured record of intake, findings, enrichment,
  timeline, root cause, and recommendations; the report's single source of truth
- **HTML report** (`bec-report.html`) — self-contained, seven sections:
  1. Executive summary with severity, dwell time, IOC hits, and files exfiltrated
  2. Suspicious ASN/ISP, OS, user agent, country, city, IPs, and phishing email analysis,
     including the legitimate-vs-observed comparison and threat-intel enrichment results
  3. SharePoint/OneDrive download spike and files viewed
  4. Suspicious Microsoft Graph API calls
  5. Unified UTC timeline with response metrics
  6. Root cause analysis (5 Whys)
  7. Recommendations as an owner/priority/deadline action-item table
- **Raw evidence exports** — retained alongside the case file, referenced but not embedded
- All IOCs in the rendered report are defanged; all interpolated values are HTML-escaped
