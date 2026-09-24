import { Hono } from 'hono';
import { revokeToken } from '@/services/tokens';

export const revokeRoutes = new Hono();

// RFC 7009. Always 200, even for a token that does not exist -- an
// attacker probing which tokens are valid learns nothing from the
// response either way.
revokeRoutes.post('/revoke', async (c) => {
  const form = await c.req.parseBody();
  const token = typeof form.token === 'string' ? form.token : undefined;
  if (token !== undefined) {
    await revokeToken(token);
  }
  return c.body(null, 200);
});
