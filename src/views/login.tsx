import type { FC } from 'hono/jsx';
import { Layout } from '@/views/layout';
import type { PendingRequest } from '@/views/pendingRequest';

const HiddenFields: FC<{ pending: PendingRequest }> = ({ pending }) => (
  <>
    <input type="hidden" name="client_id" value={pending.clientId} />
    <input type="hidden" name="redirect_uri" value={pending.redirectUri} />
    <input type="hidden" name="scope" value={pending.scope} />
    {pending.state !== undefined && <input type="hidden" name="state" value={pending.state} />}
    <input type="hidden" name="code_challenge" value={pending.codeChallenge} />
    {pending.nonce !== undefined && <input type="hidden" name="nonce" value={pending.nonce} />}
  </>
);

export const LoginPage: FC<{ pending: PendingRequest; clientName: string; error?: string }> = ({
  pending,
  clientName,
  error,
}) => (
  <Layout title="Sign in">
    <h1>
      Sign in to continue to <strong>{clientName}</strong>
    </h1>
    {error !== undefined && (
      <p class="error" role="alert">
        {error}
      </p>
    )}
    <form method="post" action="/authorize/login">
      <HiddenFields pending={pending} />
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required autocomplete="username" />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password" />
      <button type="submit">Sign in</button>
    </form>
  </Layout>
);
