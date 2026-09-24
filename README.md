# idbroker

[![CI](https://github.com/sriharifortitude/idbroker/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/idbroker/actions/workflows/ci.yml)

A minimal, correct OpenID Connect provider. Not a feature-complete
identity platform — one flow (Authorization Code, PKCE mandatory), done
in a way that survives the failure modes that actually matter: a stolen
refresh token, an intercepted authorization code, a compromised signing
key. Nothing here is a stateless JWT access token you can't take back;
nothing here accepts the weaker PKCE method just because some client
somewhere might still ask for it.

## What it does

- **Authorization Code + PKCE (S256), and nothing else.** No implicit
  flow, no resource-owner-password grant, no "plain" PKCE fallback —
  none of them exist in the code, not behind a flag. See
  [ADR 3](docs/adr/0003-pkce-mandatory-s256-only.md).
- **Opaque, hashed, revocable tokens** — access tokens, refresh tokens,
  authorization codes and the browser login session are all random
  256-bit values; only their SHA-256 hash is ever stored. The one JWT
  is the ID token, which is what OIDC actually specifies that shape for.
  See [ADR 1](docs/adr/0001-opaque-revocable-tokens.md).
- **Refresh token rotation with reuse detection.** Every refresh
  redeems for a new pair and invalidates itself. A token presented a
  second time — theft, not a retry — revokes every token descended from
  the same authorization, not just the one token. An authorization code
  replayed a second time gets identical treatment, per the OAuth 2.0
  Security BCP. See [ADR 2](docs/adr/0002-refresh-token-rotation-and-reuse-detection.md).
- **Rotating RS256 signing keys.** `/jwks.json` publishes the active key
  and any recently-retired one still inside its verification grace
  window, so rotating keys (`npm run rotate-keys`) never breaks a token
  that was issued moments before.
- **A server-rendered login and consent screen** — no client-side
  framework, no JS the user's credentials ever pass through beyond the
  browser's own form submission.
- **Exact `redirect_uri` matching.** No prefix, no wildcard. An unknown
  client or an unregistered `redirect_uri` gets an error page shown
  directly, never a redirect — the one class of `/authorize` failure
  that must not send the browser anywhere, because redirect_uri itself
  is what's unproven at that point.

## Running it

    docker compose up -d --wait        # Postgres 17 on 127.0.0.1:5436
    cp .env.example .env
    npm install
    npx prisma migrate deploy
    npm run db:seed                    # demo@example.com / "correct horse battery staple", client "demo-app"
    npm run dev                        # :3000

Registering a real client (not the seeded demo one) is a CLI command,
deliberately not an HTTP endpoint — see
[ADR 1's](docs/adr/0001-opaque-revocable-tokens.md) reasoning applied to
attack surface generally:

    npm run register-client -- --id my-app --name "My App" --type public \
      --redirect-uri https://app.example.com/callback

A confidential client (one that can keep a secret — a server-side app,
not a browser or mobile app) gets `--type confidential`; the generated
`client_secret` is printed once and is not recoverable afterward.

## Endpoints

| endpoint | purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /jwks.json` | Public signing keys |
| `GET /authorize` | Starts the flow: login, then consent |
| `POST /token` | Exchanges a code, or rotates a refresh token |
| `GET /userinfo` | Claims for a bearer access token |
| `POST /revoke` | RFC 7009 — revokes a token's whole family |
| `POST /logout` | Ends the browser session |

## Checks

    npm run typecheck
    npm run lint
    npm test                 # pure logic: PKCE, token rotation's reuse-detection
                              # state machine, JWT construction, key rotation —
                              # no database
    npm run test:integration # the full flow against the real database: login,
                              # consent, code exchange, refresh rotation, reuse
                              # detection, code replay, revocation, confidential-
                              # client authentication

The reuse-detection tests are the ones worth reading first if you're
deciding whether to trust this: `tests/integration/oidcFlow.test.ts`
actually rotates a refresh token, then replays the token that rotation
just invalidated, and asserts that *the legitimate, most-recently-issued
token from the honest rotation* also stops working — not just that the
stolen copy is rejected.

## What it deliberately does not do

- **No dynamic client registration (RFC 7591).** Clients are registered
  by an admin running a script against the database, not by an HTTP
  request — one less thing exposed to the internet.
- **No multi-factor authentication.** The single most requested
  follow-up feature this would need before handling anything that
  actually matters; not built, not pretended.
- **No social login / external IdP federation.** This *is* the identity
  provider; it doesn't delegate to one.
- **No client_credentials grant.** Machine-to-machine tokens are a
  natural, contained extension of the token-issuing code that already
  exists — deliberately left out of v0.1.0 to keep the surface this
  release actually claims to have gotten right small.
- **Signing keys live in the same database as everything else.** No
  KMS/HSM integration. A real deployment handling anything sensitive
  would want the private key material somewhere a database backup
  can't casually reveal it; stated as a real limitation of this
  version, not solved by pretending the database is that place.

## Licence

Business Source License 1.1 (converts to MIT four years after each
version's release). See [LICENSE](LICENSE).
