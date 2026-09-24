import { Hono } from 'hono';
import { lookupAccessToken } from '@/services/tokens';
import { prisma } from '@/db/client';

export const userinfoRoutes = new Hono();

userinfoRoutes.get('/userinfo', async (c) => {
  const authHeader = c.req.header('Authorization');
  if (authHeader?.startsWith('Bearer ') !== true) {
    return c.json({ error: 'invalid_token' }, 401);
  }
  const token = authHeader.slice('Bearer '.length);
  const info = await lookupAccessToken(token);
  if (info === null) return c.json({ error: 'invalid_token' }, 401);

  const scopes = info.scope.split(' ');
  const claims: Record<string, unknown> = { sub: info.userId };
  if (scopes.includes('profile') || scopes.includes('email')) {
    const user = await prisma.user.findUnique({ where: { id: info.userId } });
    if (user !== null && scopes.includes('email')) {
      claims.email = user.email;
    }
  }
  return c.json(claims);
});
