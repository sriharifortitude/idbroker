// Client registration is deliberately not an HTTP endpoint (no RFC 7591
// dynamic registration here) -- one more piece of attack surface this
// service does not expose. Registering a client is an admin action, run
// from wherever the database credentials already live.
//
//   npm run register-client -- --id my-app --name "My App" --type public \
//     --redirect-uri https://app.example.com/callback
//
//   npm run register-client -- --id my-server --name "My Server" --type confidential \
//     --redirect-uri https://server.example.com/callback
import { parseArgs } from 'node:util';
import { randomUUID } from 'node:crypto';
import { prisma } from '@/db/client';
import { hashPassword } from '@/core/password';

async function main() {
  const { values } = parseArgs({
    options: {
      id: { type: 'string' },
      name: { type: 'string' },
      type: { type: 'string' }, // "public" | "confidential"
      'redirect-uri': { type: 'string', multiple: true },
    },
  });

  if (values.id === undefined || values.name === undefined || values.type === undefined) {
    console.error('usage: register-client --id ID --name NAME --type public|confidential --redirect-uri URI [--redirect-uri URI ...]');
    process.exit(2);
  }
  const type = values.type === 'public' ? 'PUBLIC' : values.type === 'confidential' ? 'CONFIDENTIAL' : null;
  if (type === null) {
    console.error('--type must be "public" or "confidential"');
    process.exit(2);
  }
  const redirectUris = values['redirect-uri'] ?? [];
  if (redirectUris.length === 0) {
    console.error('at least one --redirect-uri is required');
    process.exit(2);
  }

  let secret: string | undefined;
  let secretHash: string | null = null;
  if (type === 'CONFIDENTIAL') {
    secret = randomUUID() + randomUUID();
    secretHash = await hashPassword(secret);
  }

  await prisma.client.create({
    data: { id: values.id, name: values.name, type, secretHash, redirectUris },
  });

  console.log(`registered client "${values.id}" (${type})`);
  if (secret !== undefined) {
    console.log(`client_secret (shown once, not recoverable): ${secret}`);
  }
}

main()
  .catch((err: unknown) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => void prisma.$disconnect());
