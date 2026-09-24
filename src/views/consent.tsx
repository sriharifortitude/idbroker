import type { FC } from 'hono/jsx';
import { Layout } from '@/views/layout';
import type { PendingRequest } from '@/views/pendingRequest';

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Confirm who you are',
  profile: 'Your name',
  email: 'Your email address',
};

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

export const ConsentPage: FC<{ pending: PendingRequest; clientName: string; userEmail: string }> = ({
  pending,
  clientName,
  userEmail,
}) => (
  <Layout title="Authorize">
    <h1>
      <strong>{clientName}</strong> wants to access your account
    </h1>
    <p>Signed in as {userEmail}</p>
    <p>This will let {clientName}:</p>
    <ul class="scope-list">
      {pending.scope.split(' ').map((scope) => (
        <li key={scope}>{SCOPE_DESCRIPTIONS[scope] ?? scope}</li>
      ))}
    </ul>
    <form method="post" action="/authorize/consent">
      <HiddenFields pending={pending} />
      <button type="submit" name="decision" value="approve">
        Allow
      </button>
      <button type="submit" name="decision" value="deny" class="secondary">
        Deny
      </button>
    </form>
  </Layout>
);
