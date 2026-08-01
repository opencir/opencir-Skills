# Workflows: Investigating Business Email Compromise

Query reference for each report section. Set `$upn` and the time window once, then work down.

```powershell
$upn   = "user@contoso.com"
$start = (Get-Date).AddDays(-30)
$end   = Get-Date
Connect-ExchangeOnline
```

```kql
// KQL equivalents assume Log Analytics / Sentinel with SigninLogs exported
let upn = "user@contoso.com";
let win = 30d;
```

---

## Investigation pipeline

```
Case intake (analyst supplies legitimate baseline)
  |
  v
[Evidence collection]
  +-- Entra sign-in logs      -> IP, ASN, geo, device, user agent
  +-- UAL UserLoggedIn        -> session correlation
  +-- MailItemsAccessed       -> what mail was read
  +-- FileDownloaded/Accessed -> what was exfiltrated
  +-- Graph activity/consent  -> persistence
  |
  v
[Baseline comparison]  observed vs legitimate -> MATCH | DEVIATION | UNKNOWN
  |
  v
[IOC enrichment via MCP]  IPs, domains, URLs -> verdicts
  |
  v
[Evasion check]  Set-AdminAuditLogConfig, eDiscovery purge, delete rules -> evidentiary gaps
  |
  v
[Timeline merge]  all sources, normalised to UTC
  |
  v
[Root cause 5 Whys] -> [Recommendations] -> [HTML report]
```

---

## Section 2: Sign-in analysis — ASN, ISP, geo, device, user agent

### Entra sign-in logs (KQL)

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ "user@contoso.com"
| extend asn      = tostring(parse_json(AutonomousSystemNumber))
| extend city     = tostring(LocationDetails.city)
| extend country  = tostring(LocationDetails.countryOrRegion)
| extend os       = tostring(DeviceDetail.operatingSystem)
| extend browser  = tostring(DeviceDetail.browser)
| extend deviceId = tostring(DeviceDetail.deviceId)
| project TimeGenerated, IPAddress, asn, country, city, os, browser, deviceId,
          AppDisplayName, ClientAppUsed, UserAgent,
          ResultType, ResultDescription,
          mfa = tostring(AuthenticationRequirement),
          ca  = tostring(ConditionalAccessStatus)
| order by TimeGenerated asc
```

### Distinct ASN / country / device summary — the baseline deviation view

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ "user@contoso.com"
| where ResultType == 0                       // successful sign-ins only
| extend asn     = tostring(AutonomousSystemNumber),
         country = tostring(LocationDetails.countryOrRegion),
         os      = tostring(DeviceDetail.operatingSystem),
         browser = tostring(DeviceDetail.browser)
| summarize signins = count(),
            first = min(TimeGenerated),
            last  = max(TimeGenerated),
            ips   = make_set(IPAddress, 20)
        by asn, country, os, browser
| order by signins asc                        // rare combinations first — these are the leads
```

Anything appearing once or twice at the top of this list, against a user with a stable
history, is where the investigation starts.

### Impossible travel

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ "user@contoso.com" and ResultType == 0
| extend country = tostring(LocationDetails.countryOrRegion)
| sort by TimeGenerated asc
| extend prevCountry = prev(country), prevTime = prev(TimeGenerated), prevIp = prev(IPAddress)
| where country != prevCountry
| extend gapMinutes = datetime_diff('minute', TimeGenerated, prevTime)
| where gapMinutes < 240                      // < 4h between different countries
| project prevTime, prevCountry, prevIp, TimeGenerated, country, IPAddress, gapMinutes
```

### Non-interactive sign-ins — where token replay hides

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ "user@contoso.com"
| summarize count(), make_set(AppDisplayName, 10) by IPAddress,
            tostring(LocationDetails.countryOrRegion)
| order by count_ desc
```

Interactive sign-in review alone misses AiTM token replay. Always check both.

### UAL equivalent (no Sentinel)

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end `
  -UserIds $upn -Operations UserLoggedIn,UserLoginFailed -ResultSize 5000 |
  Select-Object CreationDate, Operations,
    @{n='IP';   e={ ($_.AuditData | ConvertFrom-Json).ClientIP }},
    @{n='UA';   e={ ($_.AuditData | ConvertFrom-Json).ExtendedProperties |
                    Where-Object Name -eq 'UserAgent' | Select-Object -Expand Value }} |
  Sort-Object CreationDate
```

### Brute force and MFA errors (UAL)

When Entra sign-in logs are unavailable or you want a second source, the UAL carries its own
brute-force and MFA signal:

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds $upn `
  -Operations IdsLocked,UserLoginFailed,UserStrongAuthClientAuthNRequired,`
UserStrongAuthClientAuthNRequiredInterrupt -ResultSize 5000 |
  Select-Object CreationDate, Operations, UserIds,
    @{n='IP'; e={ ($_.AuditData | ConvertFrom-Json).ClientIP }} |
  Sort-Object CreationDate
```

| Operation | Meaning |
|---|---|
| `IdsLocked` | Account locked after repeated bad credentials |
| `UserKey="Not Available"` (search text within failed-login records) | Attacker guessed a UPN that does not exist in the tenant |
| `UserLoginFailed` | A single failed login |
| `UserStrongAuthClientAuthNRequired` | MFA challenge issued |
| `UserStrongAuthClientAuthNRequiredInterrupt` | MFA challenge issued and **failed** — the attacker had the password but not the second factor |

A successful login immediately following a burst of these is the signature of a successful
brute force or password-spray. **False-positive note:** a client performing a full mailbox
sync can generate a similar burst of rapid auth events; check the client/app field before
calling a burst malicious.

---

## Section 2 (cont.): Phishing email and mailbox persistence

### Locate the lure and everyone who received it

```powershell
# Requires Security & Compliance / Defender for Office 365
Get-MessageTrace -SenderAddress "attacker@lure.example" `
  -StartDate $start -EndDate $end |
  Select-Object Received, SenderAddress, RecipientAddress, Subject, Status
```

```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where SenderFromAddress =~ "attacker@lure.example"
     or Subject has "Action required"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject,
          DeliveryAction, ThreatTypes, UrlCount
```

```kql
// Who actually clicked
UrlClickEvents
| where TimeGenerated > ago(30d)
| where AccountUpn =~ "user@contoso.com"
| project TimeGenerated, Url, ActionType, IsClickedThrough, ThreatTypes
```

### Attacker inbox rules — the highest-value single artefact

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end `
  -Operations New-InboxRule,Set-InboxRule,UpdateInboxRules -ResultSize 5000 |
  ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    [pscustomobject]@{
      Time  = $_.CreationDate
      User  = $d.UserId
      IP    = $d.ClientIP
      Rule  = ($d.Parameters | Where-Object Name -eq 'Name').Value
      Move  = ($d.Parameters | Where-Object Name -like '*MoveToFolder*').Value
      Words = ($d.Parameters | Where-Object Name -like '*SubjectContainsWords*').Value
      Fwd   = ($d.Parameters | Where-Object Name -like '*Forward*').Value
    }
  } | Sort-Object Time
```

Rules moving `invoice`, `payment`, `wire`, `bank`, `remittance`, or the attacker's own domain
to **RSS Feeds**, **Conversation History**, **Archive**, or **Deleted Items** are BEC
concealment (T1114.003 / F1022), not user housekeeping.

### Grading inbox rules: TP vs FP

Apply this before writing any rule into the incident narrative. Based on Microsoft's
[inbox manipulation rules alert-grading
playbook](https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules):

| Signal | Likely TP | Likely FP / needs more evidence |
|---|---|---|
| Keyword filter | `invoice`, `payment`, `wire`, `bank`, `phish`, `spam`, `do not reply`, or a term matching the org's own fraud vocabulary | Personal/team filing terms (`newsletter`, sender's own name, a project code the user owns) |
| No keyword filter at all | Rule applies to **all** mail — itself suspicious | N/A — absence of a filter is never reassuring on its own |
| Destination folder | `RSS Feeds`, `Conversation History`, `Archive`, `Deleted Items`, paired with `MarkAsRead` | A named project/client folder the user demonstrably uses elsewhere |
| Delete-all | Deletes all incoming mail, no filter | Never benign at the "all mail" scope — even a legitimate power-user filter narrows first |
| Creation context | Follows an anomalous sign-in (new ASN/country/UA), or a prior Entra ID Protection / Defender alert on the same user | Created from the user's normal device/location, no adjacent anomaly, user confirms intent |
| Correlated incident | Other TP alerts already attached to the same incident | Rule is the only signal on an otherwise clean account |

None of these is individually dispositive except the delete-all pattern. Grade on the
combination and record the rationale — this is what feeds Step 3 of the SKILL workflow and
the `assessment` field of each `mailbox_persistence` case-file entry.

### Advanced hunting (Defender XDR / MDCA) — `CloudAppEvents`

Where Microsoft Defender for Cloud Apps is licensed, `CloudAppEvents` gives an alternate,
often faster, path to the same inbox-rule and baseline data as the UAL queries above —
useful for a first pass in the Defender XDR portal before pulling raw UAL exports.

```kql
// New/changed inbox rules for a specific user in a time window
let start_date = now(-10h);
let end_date = now();
let user_id = ""; // Entra object ID of the affected user
CloudAppEvents
| where Timestamp between (start_date .. end_date)
| where AccountObjectId == user_id
| where Application == @"Microsoft Exchange Online"
| where ActionType in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| project Timestamp, ActionType, CountryCode, City, ISP, IPAddress, RuleConfig = RawEventData.Parameters, RawEventData
```

`RuleConfig` carries the new rule's keyword filters, destination folder, and delete/forward
actions — this is the field to read for the TP/FP grading above.

```kql
// 60-day ISP baseline — is the alert's ISP one this user has used before?
let alert_date = now(); // set to the alert timestamp
let timeback = 60d;
let userid = ""; // Entra object ID
CloudAppEvents
| where Timestamp between ((alert_date-timeback)..(alert_date-1h))
| where AccountObjectId == userid
| make-series ActivityCount = count() default = 0 on Timestamp from (alert_date-timeback) to (alert_date-1h) step 12h by ISP
```

```kql
// 60-day country/region baseline
let alert_date = now();
let timeback = 60d;
let userid = "";
CloudAppEvents
| where Timestamp between ((alert_date-timeback)..(alert_date-1h))
| where AccountObjectId == userid
| make-series ActivityCount = count() default = 0 on Timestamp from (alert_date-timeback) to (alert_date-1h) step 12h by CountryCode
```

```kql
// 60-day user-agent baseline
let alert_date = now();
let timeback = 60d;
let userid = "";
CloudAppEvents
| where Timestamp between ((alert_date-timeback)..(alert_date-1h))
| where AccountObjectId == userid
| make-series ActivityCount = count() default = 0 on Timestamp from (alert_date-timeback) to (alert_date-1h) step 12h by UserAgent
```

An ISP, country, or user agent with zero prior occurrences in 60 days that then appears at
the moment of rule creation is the same "new ASN + new country + new UA" deviation stack
described in Section 2 — `CloudAppEvents` just gets there without a Sentinel workspace.

### Current rules and delegate permissions still in place

```powershell
Get-InboxRule -Mailbox $upn |
  Select-Object Name, Enabled, Description, ForwardTo, RedirectTo, MoveToFolder, DeleteMessage

Get-MailboxPermission     -Identity $upn | Where-Object { $_.User -notlike "NT AUTHORITY\*" }
Get-RecipientPermission   -Identity $upn | Where-Object { $_.Trustee -notlike "NT AUTHORITY\*" }
Get-Mailbox $upn | Select-Object ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
```

### Transport rules and broader permission changes

Inbox rules are per-mailbox; **transport rules** (mail-flow rules) are organisation-wide and
require Exchange admin rights — their presence in a BEC case points at a higher-privilege
compromise than a single mailbox takeover.

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end `
  -Operations New-TransportRule,Set-TransportRule -ResultSize 5000 |
  ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    [pscustomobject]@{
      Time = $_.CreationDate; User = $d.UserId
      Rule = ($d.Parameters | Where-Object Name -eq 'Name').Value
      Detail = ($d.Parameters | Where-Object Name -in
        'RedirectMessageTo','BlindCopyTo','DeleteMessage','SubjectContainsWords') |
        ForEach-Object { "$($_.Name)=$($_.Value)" }
    }
  } | Sort-Object Time

Get-TransportRule | Select-Object Name, State, RedirectMessageTo, BlindCopyTo, Description
```

Permission and account-creation operations beyond `Add-MailboxPermission` grant the same
practical access (SendAs, folder-level read) and are just as often used for persistence:

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end -ResultSize 5000 -Operations `
  Add-RecipientPermission,Add-MailboxFolderPermission,Set-MailboxFolderPermission,`
"Add member to role","Add member to group","Added user" |
  ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    [pscustomobject]@{ Time=$_.CreationDate; Op=$_.Operations; Actor=$d.UserId
                       Target=$d.ObjectId; Detail=($d.ModifiedProperties | ConvertTo-Json -Compress) }
  } | Sort-Object Time
```

`Added user` and `Add member to role`/`group` catch an attacker creating a fallback account
or self-elevating an existing one — cross-check any hit against IT/HR's expected joiner or
role-change list before assuming it is illegitimate, and treat unexplained hits as persistence
that will outlive a mailbox-level remediation. Roles worth alerting on if newly assigned:
Global Administrator, Exchange Administrator, SharePoint Administrator, User Administrator,
Password Administrator, Conditional Access Administrator, Security Administrator.

### What mail was actually read (requires Audit Premium)

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end `
  -UserIds $upn -Operations MailItemsAccessed -ResultSize 5000 |
  ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    [pscustomobject]@{
      Time     = $_.CreationDate
      IP       = $d.ClientIP
      App      = $d.ClientAppId
      Type     = $d.OperationProperties  # Sync vs Bind
      Folders  = ($d.Folders | ForEach-Object { $_.Path }) -join '; '
      MsgCount = ($d.Folders | ForEach-Object { $_.FolderItems.Count } | Measure-Object -Sum).Sum
    }
  } | Sort-Object Time
```

`Sync` access indicates a bulk mailbox pull; `Bind` indicates individual message reads.

**Identifying exactly which emails were read**, once sessions belonging to the attacker are
known (from IP/ASN identified in Step 4), is a three-step pivot:

1. Filter `MailItemsAccessed` events to the attacker's `SessionId` or IP to isolate their
   activity from the legitimate user's. `Bind` events carry an `OperationCount` — bind
   operations within a 2-minute window are aggregated into one record, so a high count
   means many individual messages read in a short burst.
2. Each event's `Folders` field contains `InternetMessageId` value(s) for the accessed mail —
   this is the durable identifier for a specific message, independent of mailbox or folder.
3. Look up each `InternetMessageId` in `Get-MessageTrace` (10-day history limit) to recover
   sender, subject, and recipient metadata for what was actually exposed.

`MailItemsAccessed` requires Audit Premium (E5) — where it is unavailable, do not attempt to
enumerate specific messages; state in the report that "which messages were read" is
unanswerable from available logs, and scope impact from mailbox contents instead (see
Step 5's phishing/impact analysis in `standards.md`).

### Evasion and anti-forensics

An attacker who suspects logging will expose them may try to defeat the very evidence this
skill relies on. Check for all three before treating "nothing more found" as reassuring:

```powershell
# Audit Log disabled — itself a UAL event
Search-UnifiedAuditLog -StartDate $start -EndDate $end `
  -Operations Set-AdminAuditLogConfig -ResultSize 100 |
  Select-Object CreationDate, UserIds, @{n='Params';e={($_.AuditData|ConvertFrom-Json).Parameters}}
```

```powershell
# eDiscovery / compliance search used to purge evidence
Search-UnifiedAuditLog -StartDate $start -EndDate $end -ResultSize 500 -Operations `
  "New-ComplianceSearchAction","eDiscovery search started or exported" |
  Select-Object CreationDate, UserIds, Operations,
    @{n='Detail'; e={ ($_.AuditData | ConvertFrom-Json).Parameters }}
```

If `Set-AdminAuditLogConfig` shows logging toggled off, treat the surrounding window as an
**evidentiary gap**, not as a quiet period — say explicitly in the report "logging was
disabled from X to Y; this investigation cannot rule out activity in that window," rather
than letting the absence of events read as an absence of activity.

Purge rules — a rule or manual action that deletes a sent message and its replies — hide a
fraudulent conversation from the real user. Check delete actions against `Sent Items`, not
just `Inbox`, alongside the inbox-rule grading in Step 3.

Any `New-ComplianceSearchAction` with a `-Purge` action, or an `eDiscovery search started or
exported` alert, run by an account outside the legal/eDiscovery team during the incident
window is a red flag on its own, regardless of what it searched for.

---

## Section 3: SharePoint / OneDrive download spike

### Baseline the user against themselves

```kql
let upn = "user@contoso.com";
let incidentStart = datetime(2026-07-20T14:00:00Z);
OfficeActivity
| where TimeGenerated between (ago(30d) .. incidentStart)
| where UserId =~ upn and Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize daily = count() by bin(TimeGenerated, 1d)
| summarize baselineMean = avg(daily), baselineMax = max(daily)
```

```kql
// Incident window against that baseline
OfficeActivity
| where TimeGenerated > datetime(2026-07-20T14:00:00Z)
| where UserId =~ "user@contoso.com"
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize downloads = count(),
            files = make_set(OfficeObjectId, 100),
            sites = make_set(Site_Url, 20),
            ips   = make_set(ClientIP, 10)
        by bin(TimeGenerated, 1h)
| order by downloads desc
```

Report the **ratio**: incident-window rate ÷ 30-day daily mean.

### Files viewed but not downloaded — still exposure

```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId =~ "user@contoso.com" and Operation == "FileAccessed"
| project TimeGenerated, OfficeObjectId, Site_Url, ClientIP, UserAgent
| order by TimeGenerated asc
```

### External sharing links

`AddedToSecureLink` shows documents shared via a link scoped to specific people, including
external recipients — capture this alongside downloads, since sharing a link is exfiltration
even when the recipient never triggers a `FileDownloaded` event server-side.

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds $upn `
  -Operations AddedToSecureLink -ResultSize 5000 |
  ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    [pscustomobject]@{ Time=$_.CreationDate; File=$d.SourceFileName; Site=$d.SiteUrl
                       SharedWith=$d.TargetUserOrGroupName; External=$d.TargetUserOrGroupType }
  } | Where-Object { $_.External -notmatch 'Member|Internal' } | Sort-Object Time
```

### UAL equivalent

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds $upn `
  -Operations FileDownloaded,FileAccessed,FileSyncDownloadedFull -ResultSize 5000 |
  ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    [pscustomobject]@{ Time=$_.CreationDate; Op=$d.Operation; File=$d.SourceFileName
                       Site=$d.SiteUrl; IP=$d.ClientIP }
  } | Group-Object { $_.Time.ToString("yyyy-MM-dd HH") } |
      Select-Object Name, Count | Sort-Object Count -Descending
```

---

## Section 4: Microsoft Graph API abuse

### Graph calls from the attacker infrastructure

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(30d)
| where UserId == "<object-id-of-user>"
| extend path = tostring(parse_url(RequestUri).Path)
| summarize calls = count(),
            uris  = make_set(path, 20),
            ips   = make_set(IPAddress, 10)
        by AppId, ServicePrincipalId
| order by calls desc
```

```kql
// Narrow to mail and file scopes — the BEC-relevant ones
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(30d)
| extend path = tostring(parse_url(RequestUri).Path)
| where path has_any ("/messages", "/mailFolders", "/drive", "/sendMail")
| where UserId == "<object-id-of-user>"
| project TimeGenerated, AppId, RequestMethod, path, IPAddress, ResponseStatusCode
| order by TimeGenerated asc
```

### Illicit consent grants and new service principals

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application",
                          "Add delegated permission grant",
                          "Add app role assignment to service principal",
                          "Add service principal",
                          "Add service principal credentials")
| extend actor = tostring(InitiatedBy.user.userPrincipalName)
| extend target = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, actor, target,
          props = tostring(TargetResources[0].modifiedProperties)
| order by TimeGenerated asc
```

```powershell
# Consented apps still granted mail/file scopes
Get-MgOauth2PermissionGrant -All |
  Where-Object { $_.Scope -match "Mail\.|Files\.|offline_access" } |
  Select-Object ClientId, ConsentType, PrincipalId, Scope
```

Any consent grant created inside the incident window is a **containment blocker**: password
reset and session revocation will not remove it.

---

## Section 5: Timeline construction

Merge all sources into one ordered list. Every row carries its source so the report is auditable.

| Field | Value |
|---|---|
| `timestamp` | ISO 8601, **UTC**, e.g. `2026-07-20T14:32:11Z` |
| `event` | What happened, in plain language |
| `actor` | `Threat actor`, `User`, `SOC analyst`, `IR team`, `System` |
| `source` | `SigninLogs`, `UAL:New-InboxRule`, `OfficeActivity`, `AuditLogs`, `Analyst` |

Canonical BEC milestones to place, where evidence supports each:

```
Phishing email delivered           -> EmailEvents / Get-MessageTrace
User clicked lure                  -> UrlClickEvents
Credential/token captured          -> inferred; state as inference
First attacker sign-in             -> SigninLogs (attacker ASN)
Inbox rule created                 -> UAL New-InboxRule
Mailbox bulk read                  -> MailItemsAccessed (Sync)
OAuth consent granted              -> AuditLogs Consent to application
File download spike                -> OfficeActivity FileDownloaded
Fraudulent mail sent               -> UAL Send / SendAs
Audit logging disabled (if found)  -> UAL Set-AdminAuditLogConfig
Evidence purged (if found)         -> UAL New-ComplianceSearchAction -Purge
Detection / user report            -> Alert or ticket
Containment: sessions revoked      -> Analyst action
Containment: credentials reset     -> Analyst action
Consent revoked / SP disabled      -> Analyst action
Recovery complete                  -> Analyst action
```

### Response metrics derived from the timeline

| Metric | Formula | Target |
|---|---|---|
| Dwell time | detection − initial compromise | < 24 hours |
| MTTD | triage complete − first alert | < 30 minutes |
| MTTC | containment complete − detection | < 4 hours |
| MTTR | recovery complete − detection | < 48 hours |

Timestamps that cannot be evidenced should be left `UNKNOWN`, not estimated. An estimated
initial-compromise time silently changes the dwell-time headline.

---

## Section 6: Root cause — 5 Whys

Record the evidence for each step, not just the assertion.

| Level | Question | Answer | Evidence |
|---|---|---|---|
| Why 1 | Why was fraudulent mail sent from this mailbox? | Attacker held a valid session | `SigninLogs` from attacker ASN |
| Why 2 | Why did the attacker have a valid session? | Token captured via AiTM proxy | `UrlClickEvents` + MFA satisfied without prompt |
| Why 3 | Why did AiTM succeed? | MFA method was phishable (SMS/push) | Authentication method registration |
| Why 4 | Why was a phishable method in use for a VIP? | No phishing-resistant MFA requirement | Conditional access policy review |
| Why 5 | Why was there no such requirement? | Policy scoped to admins only | Policy scope |

**Root Cause:** state it as a fixable systemic gap, not a user action.

Stop the chain when you reach something the organisation controls. "User clicked a link" is a
symptom; the absence of a control that would have made the click survivable is the cause.

---

## Section 7: Recommendations

Every row needs an owner and a deadline, or it will not happen.

| Horizon | Typical actions |
|---|---|
| Immediate (0–24h) | Revoke sessions, reset credentials, remove attacker rules and transport rules, revoke OAuth consent, remove unexplained role/group memberships and new accounts, notify counterparties on hijacked threads |
| Short-term (1–30d) | Enforce phishing-resistant MFA for the affected cohort, block legacy auth, alert on inbox-rule and transport-rule creation, alert on bulk download, alert on `Set-AdminAuditLogConfig` |
| Long-term (30d+) | Extend phishing-resistant MFA org-wide (all privileged roles, not just Global Admin), NIST-aligned password policy, enable Audit Premium for `MailItemsAccessed`, centralise O365 logging in a SIEM, implement consent governance and admin consent workflow, block external mail forwarding by policy, **four-eyes/dual-approval on bank-detail and payment-instruction changes**, targeted phishing training for high-risk roles |

---

## Evidence handling

- Export raw query output before summarising; the report cites, it does not replace, evidence
- Hash and store exports with the case reference
- Record the query, the exact time window, and the tenant timezone alongside each export
- Note explicitly where a data source was unavailable (licence, retention) — an absence of
  evidence is a finding in its own right and must not read as an absence of activity
