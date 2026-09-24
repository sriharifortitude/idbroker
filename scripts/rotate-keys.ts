// Rotates the RS256 signing key: generates a new one, retires every
// previously-active one (they keep verifying, via /jwks.json, until
// every token they signed has expired -- see core/keys.ts). Run this on
// a schedule (a quarterly cron, an incident response playbook) from
// wherever the database credentials already live -- same reasoning as
// register-client.ts for why this is a script, not an endpoint.
//
//   npm run rotate-keys
import { prisma } from '@/db/client';
import { rotateSigningKey } from '@/services/keys';

async function main() {
  const { newKid } = await rotateSigningKey();
  console.log(`rotated: new signing key ${newKid} is now active`);
}

main()
  .catch((err: unknown) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => void prisma.$disconnect());
