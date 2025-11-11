---
allowed-tools: Bash(git add:*), Bash(git status:*), Bash(git commit:*)
description: Create a git commit with co-authorship
---

## Instructions
1. Analyze current changes with git status and git diff
2. Generate appropriate commit message
3. Stage changes if necessary using git add
4. Execute git commit with co-authorship attribution

## Commit Format
Always include co-author attribution in commits:

git commit -m "Commit message title

Detailed description if needed.

Co-authored-by: Ojārs Kapteinis <ojars@kapteinis.lv>
Co-authored-by: Claude <noreply@anthropic.com>

License: CC BY-NC-ND 4.0"

## Constraints
- Both authors must be credited in every commit
- Use proper Git co-author trailer format
- Include CC BY-NC-ND 4.0 license notice in commit body
- Use author information from git config for primary author
