import { Hono } from 'hono';
import { deleteSession } from '@/services/sessions';
import { clearSessionCookie, getSessionCookie } from '@/api/session';

export const logoutRoutes = new Hono();

logoutRoutes.post('/logout', async (c) => {
  const token = getSessionCookie(c);
  if (token !== undefined) {
    await deleteSession(token);
  }
  clearSessionCookie(c);
  return c.body(null, 204);
});
