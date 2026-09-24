# 2. Refresh tokens rotate on every use, and a reused one revokes its whole family

Status: accepted — 2026-09-24

## Context

A refresh token that never changes is a single long-lived secret an
attacker only has to steal once -- from a compromised device, a logged
request, a misconfigured proxy -- to have standing access for as long as
it remains valid, which for a refresh token is routinely weeks. The
victim has no way to tell a stolen copy from their own legitimate one;
both work identically until someone notices something is wrong, if ever.

## Decision

Every refresh token redemption (`services/tokens.ts`, `rotateRefreshToken`)
issues a new access/refresh pair and immediately invalidates the
presented token by recording what replaced it
(`RefreshToken.replacedByHash`). The decision of what to do with a
presented token is a pure function of its record
(`core/refreshRotation.ts`, `decideRotation`), tested exhaustively with
plain objects rather than a database:

- No record, expired, or explicitly revoked: reject.
- Already has a `replacedByHash`: this exact token was already spent by
  a legitimate rotation. Presenting it again is not a retry -- it means
  two parties now hold what was meant to be a single-use secret, i.e.
  theft. **Revoke every token in its family**, not just this one
  (`revokeFamily`), which immediately invalidates the legitimate
  holder's current token too.
- Otherwise: rotate.

That last branch is the sharp edge of this design and is deliberate. It
means a genuine race (a client retrying a timed-out rotation request) is
indistinguishable from theft and gets the same harsh response: everyone
is logged out, the legitimate user has to sign in again. That is judged
the better failure mode -- a client is expected to treat a refresh
response as authoritative and stop using the old token immediately, not
retry it "just in case," and a security control that only fires on
*certain* misuse instead of *any* misuse is one an attacker can work
around by making their misuse look like the tolerated kind.

## Consequences

- `familyId` links every token descended from one `/authorize` grant
  (renewed indefinitely by rotation) so a single revocation
  (`revokeFamily`) reaches every access and refresh token in that
  lineage in two queries, not a token-by-token walk.
- An authorization code presented twice gets the identical treatment for
  the identical reason (`services/authCodes.ts`): the first redemption's
  `issuedFamilyId` is what a replayed second redemption revokes, per the
  OAuth 2.0 Security BCP.
- What this does not do: distinguish *why* a token was reused (a slow
  network retry vs. an attacker) or notify anyone that a family was
  revoked. A production deployment would want the latter -- an alert or
  an email to the affected user -- which is a real, stated gap in
  v0.1.0, not an oversight.
