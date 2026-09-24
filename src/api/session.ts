import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';

const COOKIE_NAME = 'idbroker_session';

export function setSessionCookie(c: Context, token: string, ttlSeconds: number): void {
  setCookie(c, COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
    maxAge: ttlSeconds,
  });
}

export function getSessionCookie(c: Context): string | undefined {
  return getCookie(c, COOKIE_NAME);
}

export function clearSessionCookie(c: Context): void {
  deleteCookie(c, COOKIE_NAME, { path: '/' });
}
