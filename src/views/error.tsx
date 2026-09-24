import type { FC } from 'hono/jsx';
import { Layout } from '@/views/layout';

/** Shown directly, never as a redirect -- for the class of /authorize
 *  error that occurs before redirect_uri can be trusted (see
 *  core/authorizeParams.ts). */
export const ErrorPage: FC<{ description: string }> = ({ description }) => (
  <Layout title="Error">
    <h1>Something's wrong with this request</h1>
    <p>{description}</p>
    <p>This isn't something you can fix here — the application that sent you did something wrong.</p>
  </Layout>
);
