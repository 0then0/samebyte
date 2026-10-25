# Security policy

## Supported versions

Security fixes target the latest stable SameByte release. Older releases are not
maintained separately; upgrade to the latest release when a fix is available.
The development branch may contain unreleased changes and is not a substitute
for a supported release.

## Report a vulnerability

Do not publish exploit details, credentials, private workflows, or sensitive
analysis output in a public issue or pull request.

Use [GitHub private vulnerability reporting](https://github.com/0then0/samebyte/security/advisories/new)
when the repository offers it. If that page is unavailable, open an issue with
only a request for a private security contact, without technical details. The
maintainer will need to establish a private channel before you send the report.
The project does not promise a fixed response time.

Include the following in the private report:

- Affected version and installation method, Node.js version, and operating system.
- A minimal reproducer, including workflow YAML and annotations when relevant.
- Expected behavior, actual behavior, impact, and any prerequisites.
- Relevant output with secrets and private infrastructure information removed.

The maintainer will assess the report, discuss a fix, and coordinate disclosure
with the reporter. Public disclosure should follow the availability of a fix or
an agreed disclosure date.

## Scope and trust model

SameByte performs local static analysis. It does not execute workflow commands,
fetch reusable workflow implementations, inspect registries, or validate artifact
signatures. Exit code `0` means no high-confidence violations were reported; it
is not a guarantee that a pipeline or supply chain is secure.

Unsupported boundaries and unresolved identities are documented limitations.
Incorrectly proving a supported artifact chain, executing untrusted workflow
content, or disclosing sensitive input may be security-relevant defects. Report
ordinary false positives and feature requests through the public issue forms
with sanitized examples.

Annotations are trusted assertions supplied by the user. Restrict who can change
them in your repository. When processing untrusted input in CI, use read-only
permissions and avoid exposing secrets. SameByte's own CI does not require
repository write access; release publication uses a separate job permission.
