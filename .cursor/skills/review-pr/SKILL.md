---
name: review-pr
description: Normal review of a pull request before skeptic-code-review. Use gh pr view and gh pr diff.
---

Review the PR the way a teammate would. Read the description, the full diff,
and surrounding call sites. Note correctness, security, test gaps, and docs.
Do not merge. Then run skeptic-code-review with that skill's prompt template
verbatim. No LGTM while blocking findings remain.
