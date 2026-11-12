---
name: workflow-planner
description: "Design a multi-step agent workflow: steps, tools, handoffs to people, and what happens when a step fails. Use when someone asks to automate a process with an AI agent."
metadata:
  scenario: agent-workflows
  tags: agents, automation, planning
---

# Workflow planner

Turn a described process into a workflow an AI agent can run safely.

## When to use
The user wants to automate recurring work (reports, intake, reviews, follow-ups) and has not yet said which steps the agent should own.

## Inputs to collect
- The trigger: what starts the work (a message, a schedule, a new file).
- The desired result and who receives it.
- Tools and data the agent may touch, and anything it must never touch.
- Who approves or takes over when the agent is unsure.

## Steps
1. Restate the process in one sentence and confirm it with the user.
2. List the steps in order. For each step write: input, action, tool, output.
3. Mark every step as **agent**, **agent + review** or **person**. Anything that spends money, sends messages outside the company or deletes data is at least *agent + review*.
4. For each step write the failure case and the fallback: retry, skip, ask a person, or stop.
5. Add a stop condition so the run cannot loop forever (maximum steps or time).
6. Write a short test plan: one normal case, one empty input, one failing tool.

## Output format
A table with columns `Step | Owner | Tool | Output | If it fails`, followed by the stop condition and the test plan.

## Quality checks
- Every step has exactly one owner.
- No step depends on information the agent was not given.
- A person can see what the agent did afterwards (log or summary).
