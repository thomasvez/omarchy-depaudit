# Contributing

## Branch protection

`main` requires every change to land through a pull request — direct pushes
are blocked (enforced for the repo owner too). The `test` CI check
(`node --check Model.js` + `npm test`) must pass before a PR can merge.

This exists because the marketplace listing tracks a specific reviewed
commit, not the branch tip: see the "Security Notice" on the plugin's
marketplace page. A PR gate keeps that distinction meaningful — new code
doesn't silently become "what installers get" without a pass first.

## Before merging a PR into main

This plugin parses untrusted input by design (project manifests, registry
and advisory responses, lockfiles) and shells out based on it. Any change
that touches how that data is parsed, rendered, or turned into a shell
command deserves a fresh look, not just green tests:

1. Run `/code-review` (or `/security-review` for anything touching
   `Process`/`find`/shell command construction, `Text` rendering of
   external data, or `state.json`/clipboard/notification handling).
2. Verify against real tool output where practical, not just fixtures —
   see the CHANGELOG for the established pattern.
3. Only then merge.

If a merged change meaningfully affects plugin behavior, consider whether
the marketplace listing (HANCORE-linux/omarchy-plugin-marketplace#3144)
should be re-validated against the new commit — editing that issue's body
triggers a fresh automated scan.
