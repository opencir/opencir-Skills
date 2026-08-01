# API Reference: Investigating Business Email Compromise

## Opencir Threat Intelligence MPC — MCP tools

Server: [`opencir/Opencir-Threat-Intelligence-MPC`](https://github.com/opencir/Opencir-Threat-Intelligence-MPC)
· stdio transport · tools are registered dynamically based on which API keys are configured.

Call these as MCP tools from the agent. Always call `threatintel_status` first — it reports which
upstream sources are actually live, and a source that is not configured must be reported as
**"not checked"**, never as "clean".

### Always available

| Tool | Arguments | Returns |
|---|---|---|
| `threatintel_status` | — | Which sources are configured; the tool list currently registered |
| `threatintel_lookup_ip` | `ip` | Aggregate IP verdict across AbuseIPDB, OTX, and GreyNoise |
| `threatintel_lookup_domain` | `domain` | Domain verdict across OTX and URLhaus |
| `threatintel_lookup_hash` | `hash` (MD5/SHA1/SHA256) | Hash verdict across OTX and MalwareBazaar |
| `threatintel_lookup_url` | `url` | URL verdict across OTX and URLhaus |
| `greynoise_ip` | `ip` | Internet background noise vs targeted activity (keyless community endpoint) |
| `feodo_tracker` | — | Active botnet C2 IP blocklist (Emotet, Dridex, QakBot, …) |

### Available when the matching key is configured

| Tool | Requires | Returns |
|---|---|---|
| `abuseipdb_check` | `ABUSEIPDB_API_KEY` | Abuse confidence score, `isp`, `usageType`, `countryCode`, report history |
| `otx_get_pulses` | `OTX_API_KEY` | Recent subscribed threat pulses |
| `otx_search_pulses` | `OTX_API_KEY` | Pulses matching a keyword — links an IOC to a named campaign |
| `urlhaus_lookup` | `ABUSECH_AUTH_KEY` | Malware-distribution URL/host records |
| `threatfox_search` | `ABUSECH_AUTH_KEY` | IOC search by malware family or tag |
| `threatfox_iocs` | `ABUSECH_AUTH_KEY` | Recent IOCs (C2 infrastructure) |
| `malwarebazaar_hash` | `ABUSECH_AUTH_KEY` | Malware sample metadata by hash |

### ASN and ISP attribution — read this before writing the report

**The MPC server exposes no dedicated ASN lookup tool.** There is no `asn_lookup`. ASN and ISP
attribution for a sign-in IP comes from three places:

1. **`abuseipdb_check`** (and the AbuseIPDB block inside `threatintel_lookup_ip`) — returns
   `isp`, `usageType`, `domain`, and `countryCode`. `usageType` is the field that distinguishes
   `Data Center/Web Hosting/Transit` from `Fixed Line ISP`, which is the core of the
   suspicious-ASN judgement.
2. **`greynoise_ip`** — community endpoint metadata, including organisation name and
   classification (`benign` / `malicious` / `unknown`).
3. **The Entra sign-in log itself** — `AutonomousSystemNumber` and `LocationDetails` are
   recorded per authentication and need no external lookup.

Deciding whether an ASN is *suspicious* is analyst judgement against the criteria table in
`standards.md`. Do not describe it in the report as a tool verdict.

### Enrichment call order for a BEC case

```
threatintel_status                        # what is actually live?
  |
  +-- for each sign-in IP:
  |     threatintel_lookup_ip  { ip }     # aggregate verdict + isp/usageType
  |     greynoise_ip           { ip }     # scanner noise vs targeted
  |
  +-- for the phishing lure:
  |     threatintel_lookup_url    { url }
  |     threatintel_lookup_domain { domain }   # both sender domain and URL domain
  |
  +-- feodo_tracker                       # any sign-in IP in active C2 infrastructure?
```

Record every result in the case file's `ioc_enrichment` array, including the negatives — "checked,
no hits" is a finding, and it is different from "not checked".

### Fallback when no MCP server is connected

| Service | Endpoint | Auth | Free-tier limit |
|---|---|---|---|
| AbuseIPDB | `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90` | `Key: <API_KEY>` | 1,000 req/day |
| GreyNoise | `GET https://api.greynoise.io/v3/community/{ip}` | `key: <API_KEY>` (optional) | rate-limited keyless |
| AlienVault OTX | `GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general` | `X-OTX-API-KEY: <KEY>` | unlimited |
| VirusTotal | `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` | `x-apikey: <KEY>` | 4 req/min |
| URLhaus | `POST https://urlhaus-api.abuse.ch/v1/url/` body `url=<url>` | `Auth-Key: <KEY>` | — |

---

## Microsoft Graph API

Base: `https://graph.microsoft.com/v1.0` · Auth: `Authorization: Bearer <token>`

### Investigation endpoints (read)

| Endpoint | Method | Least-privilege scope | Purpose |
|---|---|---|---|
| `/users/{id}/messages` | GET | `Mail.Read` | Retrieve messages for analysis |
| `/users/{id}/mailFolders/{id}/messageRules` | GET | `MailboxSettings.Read` | Enumerate inbox rules |
| `/users/{id}/mailboxSettings` | GET | `MailboxSettings.Read` | Forwarding configuration |
| `/auditLogs/signIns` | GET | `AuditLog.Read.All` | Sign-in records with IP, ASN, device |
| `/auditLogs/directoryAudits` | GET | `AuditLog.Read.All` | Consent grants, SP creation |
| `/identityProtection/riskyUsers` | GET | `IdentityRiskyUser.Read.All` | Entra ID Protection risk state |
| `/oauth2PermissionGrants` | GET | `Directory.Read.All` | Delegated permission grants |
| `/servicePrincipals` | GET | `Application.Read.All` | Registered applications |
| `/users/{id}/drive/root/delta` | GET | `Files.Read.All` | OneDrive change history |

### Containment endpoints (write — authorised responders only)

| Endpoint | Method | Scope | Effect |
|---|---|---|---|
| `/users/{id}/revokeSignInSessions` | POST | `User.RevokeSessions.All` | Invalidates refresh tokens — **do this first** |
| `/users/{id}/mailFolders/{id}/messageRules/{id}` | DELETE | `MailboxSettings.ReadWrite` | Remove attacker inbox rule |
| `/oauth2PermissionGrants/{id}` | DELETE | `DelegatedPermissionGrant.ReadWrite.All` | Revoke illicit consent |
| `/servicePrincipals/{id}` | PATCH `{"accountEnabled": false}` | `Application.ReadWrite.All` | Disable attacker service principal |

### Sign-in query example

```http
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
  ?$filter=userPrincipalName eq 'user@contoso.com'
    and createdDateTime ge 2026-07-01T00:00:00Z
  &$top=200
Authorization: Bearer <token>
```

Response fields that matter for this skill:

```json
{
  "createdDateTime": "2026-07-20T14:32:11Z",
  "ipAddress": "203.0.113.45",
  "autonomousSystemNumber": 9009,
  "location":      { "city": "Bucharest", "countryOrRegion": "RO" },
  "deviceDetail":  { "operatingSystem": "Windows 10", "browser": "Chrome 121.0.0",
                     "deviceId": "", "isCompliant": false, "trustType": "" },
  "status":        { "errorCode": 0 },
  "conditionalAccessStatus": "notApplied",
  "authenticationRequirement": "multiFactorAuthentication",
  "clientAppUsed": "Browser",
  "riskLevelDuringSignIn": "high"
}
```

An empty `deviceId` with `isCompliant: false` on a user whose baseline is a managed corporate
device is a strong signal, independent of geography.

---

## Exchange Online PowerShell

| Cmdlet | Purpose |
|---|---|
| `Search-UnifiedAuditLog` | Primary UAL query interface (`-Operations`, `-UserIds`, `-StartDate`) |
| `Get-InboxRule` | Current inbox rules for a mailbox |
| `Get-MailboxPermission` / `Get-RecipientPermission` | Delegate and Send-As permissions |
| `Get-Mailbox` | `ForwardingAddress`, `ForwardingSmtpAddress` |
| `Get-MessageTrace` | Message delivery records (last 10 days; use historical search beyond) |
| `Revoke-MgUserSignInSession` | Session revocation (Microsoft.Graph module) |

`Search-UnifiedAuditLog` returns `AuditData` as a JSON string — always `ConvertFrom-Json` it
before projecting fields. Result sets are capped; page with `-SessionId` / `-SessionCommand
ReturnLargeSet` for large windows.

---

## Sentinel / Log Analytics tables

| Table | Contents |
|---|---|
| `SigninLogs` | Interactive sign-ins with ASN, geo, device, CA result |
| `AADNonInteractiveUserSignInLogs` | Token-based sign-ins — where AiTM replay appears |
| `AuditLogs` | Directory changes, consent grants, service principal creation |
| `OfficeActivity` | UAL mirror: file operations, inbox rules, mail access |
| `MicrosoftGraphActivityLogs` | Per-request Graph API telemetry (requires diagnostic setting) |
| `EmailEvents` / `UrlClickEvents` | Defender for Office 365 mail delivery and click records |

---

## CLI Usage

```bash
# Validate a hand-edited case file before rendering
python3 scripts/process.py validate --case case.json

# Render the seven-section self-contained HTML report
python3 scripts/process.py report --case case.json --out bec-report.html

# Compute baseline deviations and download-spike risk
python3 scripts/agent.py --case case.json
```

Both scripts are Python 3.8+ standard library only — nothing to install.
