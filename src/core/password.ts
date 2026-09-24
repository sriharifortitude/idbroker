// Password hashing is the opposite problem from core/opaqueToken.ts: a
// human-chosen password has real, guessable structure, so it needs a
// slow, memory-hard hash. Argon2id, matching this portfolio's other
// password-handling service (bailey).
import { hash, verify } from '@node-rs/argon2';

export async function hashPassword(password: string): Promise<string> {
  return hash(password);
}

export async function verifyPassword(hashValue: string, password: string): Promise<boolean> {
  return verify(hashValue, password);
}
