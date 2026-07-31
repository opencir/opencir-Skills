<p align="center">
  <img src="assets/banner.png" alt="Opencir Skills" width="100%">
</p>

<div align="center">

# Opencir Skills

### An open-source cybersecurity skills library for AI agents — security research, defense, and education only

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-652-brightgreen?style=flat-square)](#whats-inside)
[![Domains](https://img.shields.io/badge/domains-30%2B-9cf?style=flat-square)](#whats-inside)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

**652 structured cybersecurity skills for defense, detection, forensics, incident response, threat intelligence, and compliance**

[Get Started](#quick-start) · [What's Inside](#whats-inside) · [Scope](#scope--intended-use) · [Contributing](#contributing)

</div>

---

> ⚠️ **Community project.** This is an independent, community-maintained project and is not affiliated with Anthropic PBC.

## Scope & intended use

This is an **open-source library for security research, defense, and education**. Every skill in this repository teaches detection, analysis, investigation, hardening, incident response, threat intelligence, or compliance — none teach how to attack, exploit, or gain unauthorized access to a system. Offensive and dual-use content (exploit walkthroughs, C2 frameworks, penetration-testing/red-team methodology, attack simulation, and similar material present in the upstream project this repo was forked from) has been deliberately removed.

If you believe a skill in this repository is inaccurate, out of scope for that goal, or needs validation, please email **b4b1e2b658134cf3a4467b5345b97d09@domainsbyproxy.com**.

## What this is

A junior analyst knows which Volatility3 plugin to run on a suspicious memory dump, which Sigma rules catch credential-dumping activity, and how to scope a cloud breach across three providers. This repo gives an AI agent that same structured knowledge — **652 skills** spanning cloud security, threat hunting, threat intelligence, digital forensics, malware analysis, SOC operations, identity and access management, incident response, compliance, and more, each following the [agentskills.io](https://agentskills.io) open standard.

Point an agent at this repo and a security investigation gets expert-level, step-by-step guidance instead of a generic guess.

## Quick start

```bash
git clone https://github.com/opencir/Opencir-Skills.git
cd Opencir-Skills
```

Works with Claude Code, GitHub Copilot, Cursor, Gemini CLI, and any [agentskills.io](https://agentskills.io)-compatible platform.

## What's inside

| Domain | Skills | Key capabilities |
|---|---|---|
| Cloud Security | 59 | AWS, Azure, GCP hardening · CSPM · cloud forensics |
| Threat Hunting | 58 | Hypothesis-driven hunts · LOTL detection · EVTX hunting · fleet hunting |
| Threat Intelligence | 50 | STIX/TAXII · MISP · OpenCTI · feed integration · actor profiling |
| Identity & Access Management | 36 | IAM hardening, PAM, zero trust identity, access review |
| Digital Forensics | 41 | Disk imaging · memory forensics · Hayabusa/KAPE/Plaso timelines |
| Malware Analysis | 39 | Static/dynamic analysis · reverse engineering · sandboxing |
| SOC Operations | 34 | Playbooks · escalation workflows · alert triage · tabletop exercises |
| Container Security | 31 | K8s RBAC · image scanning · Falco · container hardening |
| Network Security | 31 | IDS/IPS · firewall rules · VLAN segmentation · traffic analysis |
| OT/ICS Security | 29 | Modbus · DNP3 · IEC 62443 · historian defense · SCADA |
| Security Operations | 26 | SIEM correlation · log analysis · alert triage |
| Incident Response | 26 | Breach containment · ransomware response · IR playbooks |
| Vulnerability Management | 24 | Nessus · scanning workflows · patch prioritization · CVSS |
| DevSecOps | 18 | CI/CD security · Trivy IaC/image scanning · code signing |
| Zero Trust Architecture | 18 | BeyondCorp · CISA maturity model · microsegmentation |
| Endpoint Security | 17 | EDR · LOTL detection · fileless malware · persistence hunting |
| Cryptography | 15 | TLS · Ed25519 · post-quantum migration · key management |
| Phishing Defense | 14 | Email authentication · BEC detection · phishing IR |
| Ransomware Defense | 13 | Precursor detection · response · recovery · encryption analysis |
| API Security | 13 | Detection and hardening for OWASP API Top 10 issues |
| Compliance & Governance | 12 | NIST 800-30/RMF · CMMC · HIPAA · TPRM · CIS benchmarks |
| Supply Chain Security | 8 | SBOMs · dependency confusion · malicious-package triage · SLSA/Sigstore |
| AI Security | 8 | Prompt-injection defense, LLM guardrails, MCP/agentic security |
| Threat Detection | 7 | Cross-domain detection engineering |
| Deception Technology | 6 | Honeytokens · canarytokens · breach detection |
| Hardware & Firmware Security | 6 | CHIPSEC/UEFI audit · Secure Boot verification · TPM attestation · bootkit hunting |
| Application Security | 5 | Secure headers, security testing integration in CI/CD |
| Mobile Security | 3 | Static analysis and malware detection for mobile apps |
| Blockchain Security | 2 | Smart contract vulnerability analysis |
| Privacy & Compliance | 2 | GDPR, data protection |
| Other (identity, wireless, social-engineering defense, data protection, zero trust) | 6 | — |

Counts are computed directly from each skill's `subdomain` frontmatter field and will drift slightly as skills are added or reclassified — see [`index.json`](index.json) for the authoritative, current list.

## How AI agents use these skills

Each skill costs a small amount of tokens to scan (frontmatter only) and more to fully load (complete workflow), so an agent can search the whole library in a single pass without blowing its context window.

```
User prompt: "Analyze this memory dump for signs of credential theft"

Agent's internal process:

  1. Scans skill frontmatters
     → identifies relevant skills by matching tags, description, domain

  2. Loads the top matches:
     • performing-memory-forensics-with-volatility3
     • detecting-credential-dumping-techniques
     • analyzing-windows-event-logs-in-splunk

  3. Executes the structured Workflow section step-by-step
     → runs Volatility3 plugins, checks LSASS access patterns,
        correlates with event log evidence

  4. Validates results using the Verification section
     → confirms IOCs, maps findings to relevant detection frameworks
```

## Skill anatomy

Every skill follows a consistent directory structure:

```
skills/performing-memory-forensics-with-volatility3/
├── SKILL.md              ← Skill definition (YAML frontmatter + Markdown body)
├── references/
│   ├── standards.md      ← Framework mappings
│   └── workflows.md      ← Deep technical procedure reference
├── scripts/
│   └── process.py        ← Working helper scripts
└── assets/
    └── template.md       ← Filled-in checklists and report templates
```

### YAML frontmatter (real example)

```yaml
---
name: performing-memory-forensics-with-volatility3
description: >-
  Analyze memory dumps to extract running processes, network connections,
  injected code, and malware artifacts using the Volatility3 framework.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, memory-analysis, volatility3, incident-response, dfir]
nist_csf: [DE.CM-01, RS.AN-03]
version: "1.2"
license: Apache-2.0
---
```

### Markdown body sections

```markdown
## When to Use
Trigger conditions — when should an AI agent activate this skill?

## Prerequisites
Required tools, access levels, and environment setup.

## Workflow
Step-by-step execution guide with specific commands and decision points.

## Verification
How to confirm the skill was executed successfully.
```

Framework mappings referenced in skill frontmatter and `references/standards.md` may include MITRE ATT&CK (defensive/detection techniques), NIST CSF 2.0, MITRE D3FEND, and other frameworks depending on the skill. See [`mappings/`](mappings/) and [`docs/mitre-f3-mapping.md`](docs/mitre-f3-mapping.md) for mapping schemas — note that framework coverage documents in this repo were generated against the upstream project's full skill set and have not yet been fully regenerated against this pruned set; treat their exact figures as approximate until they are.

## Compatible platforms

**AI code assistants**
Claude Code (Anthropic) · GitHub Copilot (Microsoft) · Cursor · Windsurf · Cline · Aider · Continue · Roo Code · Amazon Q Developer · Tabnine · Sourcegraph Cody · JetBrains AI

**CLI agents**
OpenAI Codex CLI · Gemini CLI (Google)

**Agent frameworks & SDKs**
LangChain · CrewAI · AutoGen · Semantic Kernel · Haystack · Vercel AI SDK · Any MCP-compatible agent

All platforms that support the [agentskills.io](https://agentskills.io) standard can load these skills with zero configuration.

## Contributing

This project grows through community contributions:

**Add a new skill** — Follow the template in [CONTRIBUTING.md](CONTRIBUTING.md) and submit a PR. New skills must be defensive, analytical, or educational in nature — see [Scope & intended use](#scope--intended-use).

**Improve existing skills** — Add framework mappings, fix workflows, update tool references, or contribute scripts and templates.

**Report issues** — Found an inaccurate procedure, broken script, or a skill that doesn't belong given this repo's scope? Open an issue, or email **b4b1e2b658134cf3a4467b5345b97d09@domainsbyproxy.com**.

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you agree to uphold this code — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Community & security

🐛 [Issues](../../issues) — Bug reports and feature requests
🔒 [Security Policy](SECURITY.md) — Responsible disclosure process
📧 Validation questions or concerns about any skill's content: **b4b1e2b658134cf3a4467b5345b97d09@domainsbyproxy.com**

## Provenance

This repository was forked from [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) by Mahipal Jangra, licensed under Apache-2.0. This fork removes offensive and dual-use penetration-testing/red-team content to keep the library scoped to security research, defense, and education — see [Scope & intended use](#scope--intended-use).

## License

This project is licensed under the [Apache License 2.0](LICENSE). You are free to use, modify, and distribute these skills in both personal and commercial projects.

---

<div align="center">

Maintained by [Opencir](https://github.com/opencir). Not affiliated with Anthropic PBC.

</div>
