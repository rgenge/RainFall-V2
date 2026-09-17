# Review plan

## Scope and constraints

Review `levels00`, `levels01`, and `levels02`, including their documentation, payloads, and launch scripts, for substantive defects in formatting, writing, or technical content. Preserve all level files. Do not report cosmetic preferences, basic improvements, or speculative issues.

## Review steps

1. Inventory the three levels and read their documentation and scripts together.
2. Compare instructions, examples, addresses, payload layouts, and execution assumptions against the corresponding scripts and available repository evidence.
3. Verify disputed technical claims against primary sources when local evidence is insufficient. Use static analysis; do not execute exploit payloads or change level files.
4. Retain only concrete, demonstrable defects that affect correctness, reproducibility, or comprehension. Record precise file and line references, impact, and supporting evidence.
5. Report proven findings in priority order; state clearly if no substantive issue is established. Identify any limits to verification.

## Completion criteria

All three levels have been reviewed; every reported issue has specific evidence and file-line references; no level file has been modified.
