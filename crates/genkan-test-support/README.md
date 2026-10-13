# genkan-test-support

Test helpers shared by Genkan's crates. It provides a software passkey authenticator, built on
the `passkey` crate, that stands in for the browser and the user's device in
end-to-end tests of enrolment and sign-in.

- `device` creates a `Device`: a WebAuthn client holding at most one passkey, which answers
  discoverable requests (an empty allow list).
- `VerifiedUser` is the device's user check: presence and verification (biometric or PIN)
  always pass, so the tests exercise Genkan's user-verification requirement with the UV flag set.
- `logging::Capture` supplies an isolated native JSON tracing subscriber and parsed records.
  Attach its `Dispatch` to each complete asynchronous scenario with `with_subscriber` rather
  than setting a global subscriber. Current-span and span-list fields are disabled, matching
  the server's JSON output.

It depends on no other Genkan crate. It is a development dependency of `genkan-signin`,
`genkan-oauth` and the end-to-end tests, and is never part of a release build.
