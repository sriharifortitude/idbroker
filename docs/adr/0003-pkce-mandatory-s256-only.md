# 3. PKCE with S256 is mandatory for every client; "plain" and legacy grants do not exist

Status: accepted — 2026-09-24

## Context

The original OAuth 2.0 core spec supports several ways for a client to
prove it is the same party that started an authorization request: PKCE
(RFC 7636, added later, with an S256 and a weaker "plain" challenge
method), a confidential client's secret, or -- in older deployments --
nothing at all beyond the redirect itself, plus grant types (implicit,
resource owner password credentials) that later turned out to have
structural problems serious enough that the OAuth Security BCP and the
emerging OAuth 2.1 draft both simply remove them rather than caution
against them.

A general-purpose authorization server supports the old surface anyway,
because some integration somewhere still asks for it. This one does not
have that constraint -- it is choosing every client it will ever serve,
starting from zero.

## Decision

Every authorization request must include `code_challenge_method=S256`
and a well-formed `code_challenge`; both `core/authorizeParams.ts` and
the `/token` exchange (`core/pkce.ts`, `verifyCodeVerifier`) enforce
this with no fallback path. There is no code path that accepts
`code_challenge_method=plain` at all -- not a flag to disable it, a
branch that never executes. The implicit and resource-owner-password
grants are simply not implemented; `/token` recognises exactly two
`grant_type` values.

This applies identically to CONFIDENTIAL and PUBLIC clients. PKCE is
usually motivated as protection for public clients (mobile apps, SPAs)
that cannot keep a secret, but a confidential client's secret protects
the `/token` exchange, not the authorization code in transit on its way
there -- a code intercepted from a redirect is exactly as dangerous for
a confidential client's users as a public one's, so it gets exactly the
same requirement.

## Consequences

- An integration that only supports the plain PKCE method, or expects
  the implicit flow, cannot use this server. That is a real, immediate
  compatibility cost against a genuine (if fading) piece of the OAuth
  ecosystem, accepted because "we support it in a way we know is weaker"
  is a worse guarantee to make than "we don't support it."
- `code_challenge`'s length is checked against exactly 43 characters
  (`core/authorizeParams.ts`) -- the fixed length of base64url(SHA-256)
  -- which incidentally also rejects anyone attempting to pass a raw
  `code_verifier` as the challenge by mistake, since a valid verifier can
  be up to 128 characters.
- Every `/authorize` and `/token` unit and integration test that
  exercises the happy path constructs its challenge with
  `computeS256Challenge`, never a literal string -- there is no test
  fixture anywhere in this codebase that demonstrates the plain method
  working, because it never does.
