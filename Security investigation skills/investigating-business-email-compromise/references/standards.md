# Standards & References: Investigating Business Email Compromise

## MITRE ATT&CK References
- **T1566.002**: Phishing: Spearphishing Link — initial access vector
- **T1078.004**: Valid Accounts: Cloud Accounts — sign-in with stolen credentials or replayed token
- **T1114.002**: Email Collection: Remote Email Collection — mailbox read via client or API
- **T1114.003**: Email Collection: Email Forwarding Rule — inbox rule persistence and concealment
- **T1098.002**: Account Manipulation: Additional Email Delegate Permissions
- **T1550.001**: Use Alternate Authentication Material: Application Access Token
- **T1530**: Data from Cloud Storage Object — OneDrive/SharePoint bulk download
- **T1213.002**: Data from Information Repositories: SharePoint
- **T1657**: Financial Theft — the BEC objective

## MITRE Fight Fraud Framework (F3) v1.1
- **F1032**: Impersonate Official — attacker poses as executive or vendor
- **F1005.006**: Account Manipulation: Change of Payment Details
- **F1022**: Delete Relevant Emails — concealment of the fraudulent thread
- **F1025.003**: Electronic Funds Transfer: Wire Transfer — monetization

## NIST SP 800-61 Rev. 2 — Incident Handling
- 3.2 Detection & Analysis: evidence collection, scoping, prioritisation
- 3.3 Containment, Eradication & Recovery: session revocation before credential reset
- 3.4 Post-Incident Activity: lessons learned, timeline and metric capture

## NIST CSF 2.0 Alignment
| Function | Category | Applied in this skill |
|---|---|---|
| Detect | DE.AE-02 | Analysing sign-in and audit events for adverse activity |
| Detect | DE.CM-01 | Monitoring networks and cloud services for compromise |
| Respond | RS.MA-01 | Executing the incident response process |
| Respond | RS.AN-03 | Analysis to determine what happened and root cause |
| Respond | RS.CO-02 | Notifying internal and external stakeholders |
| Recover | RC.RP-01 | Recovery plan execution after containment |

## Suspicious ASN / ISP Assessment Criteria

There is no tool that returns "this ASN is malicious." Classification is analyst judgement.
Assess each observed ASN against the user's expected ASN using the categories below.

| ASN category | Typical `usageType` | Weight when unexpected for this user |
|---|---|---|
| Residential broadband (Comcast, BT, Deutsche Telekom) | `Fixed Line ISP` | Low — normal for remote work |
| Mobile carrier | `Mobile ISP` | Low — normal for phone access |
| Corporate / education | `Organization`, `University` | Low — expected on-network |
| Commercial VPN exit | `Data Center/Web Hosting/Transit` | **Medium-High** — legitimate privacy use exists, but not typical for corporate mailbox access |
| Cloud/hosting provider (AWS, Azure, DigitalOcean, OVH, M247, Choopa) | `Data Center/Web Hosting/Transit` | **High** — humans do not normally read mail from a datacenter |
| Tor exit node | `Reserved`/varies | **High** |
| Bulletproof or abuse-tolerant hosting | `Data Center/Web Hosting/Transit` | **Critical** |

**Scoring guidance.** Weight the *combination*, not any single field:

- Datacenter/VPN ASN **and** country deviation **and** user-agent deviation → treat as compromise
- Residential ASN in a new city, matching device and browser → likely travel; verify with the user
- Any ASN change accompanied by a new inbox rule within the same session → compromise regardless of ASN class
- Impossible travel (two sign-ins whose separation exceeds feasible travel speed) is decisive on its own

**Data sources for `usageType` and `isp`:** returned by AbuseIPDB (`abuseipdb_check`, and inside
`threatintel_lookup_ip`) and GreyNoise metadata. The Opencir MPC MCP server has no standalone ASN
lookup tool — see `api-reference.md`.

## Microsoft 365 Audit Retention

| Data source | Retention | Licence |
|---|---|---|
| Unified Audit Log | 90 days | E3 / Audit Standard |
| Unified Audit Log | 180 days | E5 / Audit Premium |
| `MailItemsAccessed` | Only if Audit Premium | E5 / Audit Premium |
| Entra sign-in logs (portal) | 30 days | P1/P2 |
| Entra sign-in logs (exported) | Workspace retention | Log Analytics |
| `MicrosoftGraphActivityLogs` | Workspace retention | P1/P2 + diagnostic setting |

Retention determines what questions can be answered. If `MailItemsAccessed` was not enabled,
"which messages were read" is unanswerable from logs — say so in the report rather than
inferring it.

## BEC Reference Statistics (FBI IC3)
- BEC remains among the highest-loss cybercrime categories reported to IC3
- Losses are dominated by wire transfer redirection and payroll diversion
- Median dwell time for cloud account compromise is measured in days, not hours — treat any
  dwell time under 24 hours as a good outcome and anything over a week as a detection failure

Cite the current IC3 Internet Crime Report for figures rather than reusing numbers from this
file; annual totals change and a stale figure in a report undermines it.

## Response Metric Targets

| Metric | Definition | Target |
|---|---|---|
| Dwell time | Initial compromise → detection | < 24 hours |
| MTTD | First alert → triage complete | < 30 minutes |
| MTTC | Detection → containment complete | < 4 hours |
| MTTR | Detection → recovery complete | < 48 hours |

## Containment Ordering (BEC-specific)

Order matters. Performing these out of sequence lets the attacker retain access:

1. **Revoke sessions and refresh tokens** (`Revoke-MgUserSignInSession`) — before password reset
2. **Reset credentials** and require re-registration of MFA if the method may be attacker-controlled
3. **Remove attacker inbox rules** and mailbox delegate permissions
4. **Revoke illicit OAuth consent grants** and disable attacker service principals — these survive
   both session revocation and password reset
5. **Block the attacker ASN/IP** via conditional access where appropriate
6. **Notify** the counterparty on any hijacked vendor or invoice thread
7. **Pivot on the attacker IP/ISP** across the tenant — search for other accounts with
   sign-ins, inbox rules, or Graph activity from the same source before closing the incident;
   a reused attacker IP is common in BEC campaigns and changes the scope from one mailbox to many

## Grading Suspicious Inbox Manipulation Rules (TP vs FP)

Adapted from Microsoft's [Alert classification for suspicious inbox manipulation
rules](https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules)
playbook. Full grading table and advanced-hunting queries are in `workflows.md`; this is
the summary judgement logic:

1. Suspicious keyword filter (`BodyContainsWords` / `SubjectContainsWords` /
   `SubjectOrBodyContainsWords`) targeting terms an attacker would want hidden, **or** no
   keyword filter at all applied to all incoming mail.
2. Destination folder (`MoveToFolder` + `MarkAsRead`) that relates to the keywords and is
   a low-visibility folder (RSS Feeds, Conversation History, Archive, Deleted Items).
3. A "delete all incoming mail" rule with no keyword filter — treat as malicious by default.
4. Corroborating context: the rule follows an anomalous sign-in, a prior Entra ID
   Protection / Defender risk alert on the same user, or is attached to an incident that
   already has other TP alerts.

A rule satisfying (3) alone is TP. A rule satisfying (1) or (2) alone is a lead, not a
verdict — confirm against (4) before writing it up as compromise evidence.

## Further Reading
- Microsoft: *Alert classification for suspicious inbox manipulation rules* (Defender XDR alert-grading playbook)
- Microsoft: *Responding to a compromised email account* (Microsoft 365 Defender documentation)
- Microsoft: *Investigate risky users / risk detections* (Entra ID Protection)
- CISA: *Enhanced Visibility and Hardening Guidance for Cloud Environments*
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide*
