import { Hono } from 'hono';
import { loadConfig } from '@/config';
import { validateAuthorizeParams } from '@/core/authorizeParams';
import { findClient } from '@/services/clients';
import { verifyPassword } from '@/core/password';
import { prisma } from '@/db/client';
import { createSession, lookupSession } from '@/services/sessions';
import { issueAuthorizationCode } from '@/services/authCodes';
import { getSessionCookie, setSessionCookie } from '@/api/session';
import { LoginPage } from '@/views/login';
import { ConsentPage } from '@/views/consent';
import { ErrorPage } from '@/views/error';
import type { PendingRequest } from '@/views/pendingRequest';

const config = loadConfig();

export const authorizeRoutes = new Hono();

/** FormData.get() returns string | File | null -- coercing a File with
 *  String() silently produces "[object Object]" instead of failing, so
 *  every field pulled from a form goes through this instead. */
function formString(value: FormDataEntryValue | null): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function pendingFromForm(form: FormData): PendingRequest {
  return {
    clientId: formString(form.get('client_id')) ?? '',
    redirectUri: formString(form.get('redirect_uri')) ?? '',
    scope: formString(form.get('scope')) ?? '',
    state: formString(form.get('state')),
    codeChallenge: formString(form.get('code_challenge')) ?? '',
    nonce: formString(form.get('nonce')),
  };
}

function errorRedirect(redirectUri: string, error: string, description: string, state: string | undefined): string {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  if (state !== undefined) url.searchParams.set('state', state);
  return url.toString();
}

// GET /authorize -- validates the request, then either the login page or
// (already-authenticated) the consent page.
authorizeRoutes.get('/authorize', async (c) => {
  const q = c.req.query();
  const client = q.client_id !== undefined ? await findClient(q.client_id) : null;
  const validation = validateAuthorizeParams(
    {
      responseType: q.response_type,
      redirectUri: q.redirect_uri,
      scope: q.scope,
      codeChallenge: q.code_challenge,
      codeChallengeMethod: q.code_challenge_method,
    },
    client,
  );

  if (!validation.ok) {
    if (!validation.redirectable) {
      return c.html(<ErrorPage description={validation.description} />, 400);
    }
    return c.redirect(errorRedirect(q.redirect_uri!, validation.error, validation.description, q.state));
  }

  const pending: PendingRequest = {
    clientId: client!.id,
    redirectUri: q.redirect_uri!,
    scope: validation.scope,
    state: q.state,
    codeChallenge: q.code_challenge!,
    nonce: q.nonce,
  };

  const sessionToken = getSessionCookie(c);
  const session = sessionToken !== undefined ? await lookupSession(sessionToken) : null;

  if (session === null) {
    return c.html(<LoginPage pending={pending} clientName={client!.name} />);
  }
  const user = await prisma.user.findUnique({ where: { id: session.userId } });
  if (user === null) {
    return c.html(<LoginPage pending={pending} clientName={client!.name} />);
  }
  return c.html(<ConsentPage pending={pending} clientName={client!.name} userEmail={user.email} />);
});

// POST /authorize/login -- verifies credentials, starts a session, and
// (on success) renders the consent page directly rather than redirecting,
// so the OAuth parameters never have to round-trip through the URL bar
// a second time.
authorizeRoutes.post('/authorize/login', async (c) => {
  const form = await c.req.formData();
  const pending = pendingFromForm(form);
  const client = await findClient(pending.clientId);
  if (client === null) {
    return c.html(<ErrorPage description="unknown client" />, 400);
  }

  const email = formString(form.get('email')) ?? '';
  const password = formString(form.get('password')) ?? '';
  const user = await prisma.user.findUnique({ where: { email } });

  const passwordOk = user !== null && (await verifyPassword(user.passwordHash, password));
  if (!passwordOk || user === null) {
    return c.html(<LoginPage pending={pending} clientName={client.name} error="Incorrect email or password." />);
  }

  const sessionToken = await createSession(user.id, config.SESSION_TTL_SECONDS);
  setSessionCookie(c, sessionToken, config.SESSION_TTL_SECONDS);

  return c.html(<ConsentPage pending={pending} clientName={client.name} userEmail={user.email} />);
});

// POST /authorize/consent -- requires an active session; issues the
// authorization code on approval, or reports access_denied on decline.
// Every field is re-validated, not trusted from the hidden form fields
// alone: they are exactly as trustworthy as the original GET request's
// query string (a client could in principle POST here directly), no more.
//
// No separate CSRF token: the session cookie is SameSite=Lax, so a
// cross-site page cannot get its own POST here to carry the victim's
// session cookie at all -- the browser sends no cookie, this handler
// sees no session, and falls back to the login page rather than
// silently acting on anyone's behalf. That is the property an anti-CSRF
// token would otherwise exist to provide; it is not skipped for lack of
// consideration.
authorizeRoutes.post('/authorize/consent', async (c) => {
  const form = await c.req.formData();
  const pending = pendingFromForm(form);
  const client = await findClient(pending.clientId);

  const validation = validateAuthorizeParams(
    {
      responseType: 'code',
      redirectUri: pending.redirectUri,
      scope: pending.scope,
      codeChallenge: pending.codeChallenge,
      codeChallengeMethod: 'S256',
    },
    client,
  );
  if (!validation.ok) {
    if (!validation.redirectable) return c.html(<ErrorPage description={validation.description} />, 400);
    return c.redirect(errorRedirect(pending.redirectUri, validation.error, validation.description, pending.state));
  }

  const sessionToken = getSessionCookie(c);
  const session = sessionToken !== undefined ? await lookupSession(sessionToken) : null;
  if (session === null) {
    return c.html(<LoginPage pending={pending} clientName={client!.name} />);
  }

  const decision = formString(form.get('decision')) ?? '';
  if (decision !== 'approve') {
    return c.redirect(errorRedirect(pending.redirectUri, 'access_denied', 'the user declined', pending.state));
  }

  const code = await issueAuthorizationCode({
    clientId: client!.id,
    userId: session.userId,
    redirectUri: pending.redirectUri,
    scope: pending.scope,
    codeChallenge: pending.codeChallenge,
    nonce: pending.nonce,
    ttlSeconds: config.AUTH_CODE_TTL_SECONDS,
  });

  const url = new URL(pending.redirectUri);
  url.searchParams.set('code', code);
  if (pending.state !== undefined) url.searchParams.set('state', pending.state);
  return c.redirect(url.toString());
});
