---
name: plan-stage
description: Run bounded apply and verify stages for a single openspec change
---

## opsx-change-apply
output: opsx-apply.md

Use operator prompt below as full scope for this run.

Load the openspec-apply-change skill to perform the task:

{task}

## opsx-change-verify
reads: opsx-apply.md
output: opsx-verify.md

Pressure-test same planning stage.

Original operator prompt:
{task}

Context from prior step:
{previous}
