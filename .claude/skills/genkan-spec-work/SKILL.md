---
name: genkan-spec-work
description: Implement or change a protocol behaviour in Genkan (OAuth, OpenID Connect, WebAuthn, SCIM, Kubernetes authentication) the way the codebase expects — from the specification text, with citations, adversarial tests and a conformance entry. Use for any security-relevant feature or fix.
---

# Specification-driven work

1. **Read the source.** Find the exact section of the RFC/W3C/OIDF specification, KEP or
   upstream source the behaviour depends on. Quote it to yourself; note MUST/SHOULD (RFC 2119,
   RFC 8174). For prior art, read the other project's code at a pinned commit. Never cite
   something you have not read; if a fact cannot be verified, write "not verified" instead of
   inventing a section number, URL, author or date.
2. **Decide and write it down where the code is.** In the module's rustdoc: what it does, the
   invariant, why (the threat or the spec rule), and the citation as a markdown reference link;
   collect several sources in a `# References` section (IEEE-like: authors, title, venue, date,
   URL/DOI). State decisions as facts about the design, not as history.
3. **Fail closed.** Ambiguous storage answers, unknown inputs and races are errors or explicit
   outcomes, never silent success. Single-use things (codes, links, ceremonies, PAR URIs,
   upstream `state`) are consumed by one atomic step (create-once, compare-and-swap, delete with
   `uid`/`resourceVersion` preconditions) before anything is issued.
4. **Test the attack, not just the happy path.** Replays, concurrent redemption (64 tasks behind
   a barrier, exactly one wins), forged or cross-site requests, wrong audience/issuer/nonce,
   expiry, disabled users, privilege boundaries (Genkan's own service account must not gain
   rights its users lack). Use the real apiserver for anything admission or RBAC related
   (`genkan-cluster-tests`).
5. **Record conformance.** Add or update the row in `docs/conformance.md`: section, requirement,
   level, code path, test name, status. Partial or not implemented is fine when stated plainly.
