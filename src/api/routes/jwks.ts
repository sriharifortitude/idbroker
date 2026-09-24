import { Hono } from 'hono';
import { loadConfig } from '@/config';
import { getPublishableJwks } from '@/services/keys';

const config = loadConfig();

export const jwksRoutes = new Hono();

jwksRoutes.get('/jwks.json', async (c) => {
  const keys = await getPublishableJwks(config.ID_TOKEN_TTL_SECONDS);
  return c.json({ keys });
});
