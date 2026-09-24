import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { loadConfig } from '@/config';
import { authorizeRoutes } from '@/api/routes/authorize';
import { tokenRoutes } from '@/api/routes/token';
import { jwksRoutes } from '@/api/routes/jwks';
import { discoveryRoutes } from '@/api/routes/discovery';
import { userinfoRoutes } from '@/api/routes/userinfo';
import { revokeRoutes } from '@/api/routes/revoke';
import { logoutRoutes } from '@/api/routes/logout';

export const app = new Hono();

app.route('/', discoveryRoutes);
app.route('/', jwksRoutes);
app.route('/', authorizeRoutes);
app.route('/', tokenRoutes);
app.route('/', userinfoRoutes);
app.route('/', revokeRoutes);
app.route('/', logoutRoutes);

app.get('/healthz', (c) => c.json({ ok: true }));

if (import.meta.url === `file://${process.argv[1]}`) {
  const config = loadConfig();
  serve({ fetch: app.fetch, port: config.PORT }, (info) => {
    console.log(`idbroker listening on http://localhost:${info.port}`);
  });
}
