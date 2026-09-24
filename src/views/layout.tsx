import type { FC, PropsWithChildren } from 'hono/jsx';

export const Layout: FC<PropsWithChildren<{ title: string }>> = ({ title, children }) => (
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>{title} — idbroker</title>
      <style>{`
        body { font: 16px/1.5 system-ui, sans-serif; max-width: 28rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
        h1 { font-size: 1.25rem; }
        label { display: block; margin-top: 1rem; font-weight: 600; }
        input[type="email"], input[type="password"] { width: 100%; padding: 0.5rem; margin-top: 0.25rem; box-sizing: border-box; border: 1px solid #888; border-radius: 4px; font-size: 1rem; }
        button { margin-top: 1.5rem; padding: 0.6rem 1.2rem; font-size: 1rem; border: none; border-radius: 4px; background: #1a1a1a; color: #fff; cursor: pointer; }
        button.secondary { background: #eee; color: #1a1a1a; margin-left: 0.5rem; }
        .error { color: #b00020; margin-top: 1rem; }
        .scope-list { margin: 1rem 0; padding-left: 1.25rem; }
      `}</style>
    </head>
    <body>{children}</body>
  </html>
);
