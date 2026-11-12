---
name: support-agent-playbook
description: "Write the rules a customer-service agent follows: how to classify requests, answer from approved sources, and hand over to a human. Use when setting up or reviewing an AI support agent."
metadata:
  scenario: agent-support
  tags: support, customer-service, handoff
---

# Support agent playbook

Define how an AI agent handles customer messages, so answers are consistent and risky cases reach a person.

## When to use
A team is putting an agent on a website, chat app or inbox, or an existing agent gives inconsistent answers.

## Inputs to collect
- Approved sources: help articles, policies, price lists. Nothing else may be quoted as fact.
- The top 10 request types and their usual answers.
- Topics that always go to a person (refunds above a limit, legal, safety, complaints about staff).
- Tone: how formal, which words to avoid.

## Steps
1. Group requests into types: question, problem, request for action, complaint, other.
2. For each type write the answer pattern: greeting, answer or next step, what the customer should do next.
3. Write the **handover rules**: the exact conditions, what the agent says to the customer, and what it passes on (summary, order number, what was already tried).
4. Write the **do not** list: no promises about outcomes, no guessing at policy, no personal data in replies.
5. Add 10 example conversations, three of which end in a handover.

## Output format
A one-page playbook with sections `Request types`, `Answer patterns`, `Handover rules`, `Do not`, `Examples`.

## Quality checks
- Every factual claim in an example points to an approved source.
- A handover message always tells the customer what happens next and roughly when.
