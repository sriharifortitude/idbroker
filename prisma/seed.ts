// Local development and the README's demo walkthrough only -- never run
// against a real deployment. Creates one user and one public client with
// a fixed, well-known password/redirect so the README's example commands
// work verbatim.
import { PrismaClient } from '@prisma/client';
import { hashPassword } from '../src/core/password';

const prisma = new PrismaClient();

async function main() {
  const passwordHash = await hashPassword('correct horse battery staple');
  await prisma.user.upsert({
    where: { email: 'demo@example.com' },
    update: {},
    create: { email: 'demo@example.com', passwordHash },
  });

  await prisma.client.upsert({
    where: { id: 'demo-app' },
    update: {},
    create: {
      id: 'demo-app',
      name: 'Demo App',
      type: 'PUBLIC',
      redirectUris: ['http://localhost:4000/callback'],
    },
  });

  console.log('seeded: user demo@example.com, client demo-app');
}

main()
  .catch((err: unknown) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => void prisma.$disconnect());
