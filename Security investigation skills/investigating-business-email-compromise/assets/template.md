# BEC Investigation Intake Checklist

Complete during Step 1. Anything unavailable is recorded as `UNKNOWN` — never guessed.

## Case
| Field | Value |
|---|---|
| Title | |
| Investigation ID | |
| Analyst | |
| Date opened (UTC) | |
| Severity | Critical / High / Medium / Low |
| Classification | CONFIDENTIAL - Internal Investigation |

## Asset Under Investigation
| Field | Value |
|---|---|
| Username / UPN | |
| Display name | |
| Department | |
| Role | |
| VIP / privileged | Yes / No |
| Manager | |

## Legitimate Baseline
Supplied by the analyst, the user's manager, or IT asset inventory.
**Do not derive these from the logs under investigation.**

| Field | Known-good value |
|---|---|
| ASN | |
| ISP | |
| Country | |
| City | |
| Device type | laptop / desktop |
| Operating system | |
| Browser | |
| Browser version | |

## Observed Activity
| Field | Observed value | Baseline verdict |
|---|---|---|
| ASN | | MATCH / DEVIATION / UNKNOWN |
| ISP | | MATCH / DEVIATION / UNKNOWN |
| Country | | MATCH / DEVIATION / UNKNOWN |
| City | | MATCH / DEVIATION / UNKNOWN |
| Device type | | MATCH / DEVIATION / UNKNOWN |
| Operating system | | MATCH / DEVIATION / UNKNOWN |
| Browser | | MATCH / DEVIATION / UNKNOWN |
| Browser version | | MATCH / DEVIATION / UNKNOWN |
| User agent (full) | | |
| IP addresses | | |

## Phishing Email
| Field | Value |
|---|---|
| Sender address | |
| Sender display name | |
| Subject | |
| URL | |
| Received (UTC) | |
| Clicked (UTC) | |
| Recipients | |
| Delivery action | Delivered / Junked / Blocked |
| SPF / DKIM / DMARC | / / |

## IOC Enrichment (threat-intel MCP)
Record negatives too — "checked, no hits" is different from "not checked".

| Indicator | Type | Tool | Verdict | Sources | Detail |
|---|---|---|---|---|---|
| | ip | `threatintel_lookup_ip` | | | |
| | ip | `greynoise_ip` | | | |
| | url | `threatintel_lookup_url` | | | |
| | domain | `threatintel_lookup_domain` | | | |
| — | — | `feodo_tracker` | | | |

## ASN Assessment
Analyst judgement per `references/standards.md`. Not a tool verdict.

| Field | Value |
|---|---|
| Observed ASN | |
| `usageType` | |
| Category | Residential / Mobile / Corporate / VPN / Hosting / Tor / Bulletproof |
| Risk | Low / Medium / High / Critical |
| Rationale | |

## Mailbox Persistence
| Time (UTC) | Type | Name | Detail | Source IP | Assessment |
|---|---|---|---|---|---|
| | Inbox rule | | | | |
| | Delegate | | | | |
| | Forwarding | | | | |

## Exfiltration
| Field | Value |
|---|---|
| 30-day daily download mean | |
| Incident-window downloads | |
| Incident window (hours) | |
| **Spike ratio** | |
| Sites affected | |
| Sensitivity labels present | |
| Files viewed (not downloaded) | |

## Graph API Activity
| Time (UTC) | App ID | App name | Operation | Scopes | IP | Calls | Assessment |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

## Timeline
| Time (UTC) | Event | Actor | Source |
|---|---|---|---|
| | Phishing email delivered | Threat actor | EmailEvents |
| | User clicked lure | User | UrlClickEvents |
| | First attacker sign-in | Threat actor | SigninLogs |
| | Inbox rule created | Threat actor | UAL |
| | Mailbox bulk read | Threat actor | MailItemsAccessed |
| | File download spike | Threat actor | OfficeActivity |
| | Detection / user report | SOC | |
| | Sessions revoked | IR team | Analyst |
| | Credentials reset | IR team | Analyst |
| | Recovery complete | IT ops | Analyst |

## Response Metrics
| Metric | Value | Target | Met |
|---|---|---|---|
| Dwell time | | < 24 hours | Yes / No |
| MTTD | | < 30 min | Yes / No |
| MTTC | | < 4 hours | Yes / No |
| MTTR | | < 48 hours | Yes / No |

## Root Cause Analysis (5 Whys)
| Level | Question | Answer | Evidence |
|---|---|---|---|
| Why 1 | | | |
| Why 2 | | | |
| Why 3 | | | |
| Why 4 | | | |
| Why 5 | | | |

**Root Cause:**

**Confidence:** High / Medium / Low —

## Recommendations
| ID | Horizon | Action | Owner | Priority | Deadline | Category | Status |
|---|---|---|---|---|---|---|---|
| 1 | Immediate | | | High | | Process / Tech / People | Open |
| 2 | Short-term | | | | | | Open |
| 3 | Long-term | | | | | | Open |

## Evidence Notes
Record any data source that was unavailable (licence gap, retention expiry).
An absence of evidence is a finding — it must not read as an absence of activity.

-
-
