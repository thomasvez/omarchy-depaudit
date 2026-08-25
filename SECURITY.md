# Security Policy

## Supported versions

This project doesn't maintain release branches — only the latest commit on
`main` is supported. If a report affects an older version, the fix will
still land as a new commit on `main` rather than a backport.

## Scope

This is a local Omarchy bar plugin: it generates a bash script from your
configured project paths/labels and the shell.json settings you (or the
in-panel settings form) provide, and runs it to invoke each ecosystem's
audit tool. The most relevant class of bug here is **command injection via
a crafted `path`, `label`, or `discoverRoots` entry** making it into that
generated script unsafely — every one of those values is expected to go
through `Model.shellQuote` before being interpolated, and a case where one
doesn't is a real vulnerability, not a style nit. Also in scope: anything
that could exfiltrate or corrupt data outside the plugin's own state
(`~/.local/state/omarchy-depaudit/`) or `shell.json`, or a finding parser
that mishandles a malicious/malformed tool response in a way that's more
than a crash (e.g. arbitrary code execution, not just a bad panel render).

Findings the audit tools themselves report (real CVEs in your
dependencies) are the product working as intended, not a vulnerability in
this plugin — report those upstream to the affected package instead.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
— the "Report a vulnerability" button under this repository's Security
tab. Include a description and, if you have one, a minimal reproduction
(a `shell.json` snippet and/or a project layout that triggers it). Please
don't open a public GitHub issue for anything exploitable until there's
been time to look at it.

> Note: private vulnerability reporting only works on **public**
> repositories. While this repo is private, that button won't be
> reachable by anyone outside it — there's no fallback channel listed
> here on purpose, so if you're reading this from outside the repo, it's
> already public and the button works.

This is a single-maintainer side project, not a company with an SLA —
expect best-effort, not guaranteed response times. A real, in-scope report
will get fixed; it just might not be fast.
