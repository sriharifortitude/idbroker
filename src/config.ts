import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().min(1),
  ISSUER: z.string().url(),
  PORT: z.coerce.number().int().positive().default(3000),
  // All TTLs in seconds. Access tokens and authorization codes are
  // deliberately short; the refresh token is what actually keeps a
  // session going, rotating on every use (docs/adr/0002).
  AUTH_CODE_TTL_SECONDS: z.coerce.number().int().positive().default(60),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(300),
  ID_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(300),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 30),
  SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 7),
});

export type Config = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    throw new Error(`invalid configuration: ${parsed.error.message}`);
  }
  return parsed.data;
}
