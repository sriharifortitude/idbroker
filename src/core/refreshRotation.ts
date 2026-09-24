// The reuse-detection decision, factored out as a pure function of a
// looked-up record and the current time -- see
// docs/adr/0002-refresh-token-rotation-and-reuse-detection.md. Keeping
// this free of Prisma means the security-critical branch (an already-
// rotated token being presented again) is tested with plain objects, not
// a real database, and every case is exhaustive and explicit rather than
// implied by whatever a query happened to return.
export interface RefreshTokenRecord {
  familyId: string;
  replacedByHash: string | null;
  revokedAt: Date | null;
  expiresAt: Date;
}

export type RotationDecision =
  | { kind: 'rotate' }
  | { kind: 'reject'; reason: 'not_found' | 'expired' | 'revoked' }
  /** The presented token was already rotated away once before -- it has
   *  been stolen or duplicated. The caller must revoke every token in
   *  familyId, not just this one. */
  | { kind: 'reuse_detected'; familyId: string };

export function decideRotation(record: RefreshTokenRecord | null, now: Date): RotationDecision {
  if (!record) return { kind: 'reject', reason: 'not_found' };
  if (record.revokedAt) return { kind: 'reject', reason: 'revoked' };
  // Checked before expiry: a stolen token presented after the legitimate
  // rotation has already happened is reuse regardless of whether it also
  // happens to be past its own expiry -- the family still needs revoking.
  if (record.replacedByHash !== null) return { kind: 'reuse_detected', familyId: record.familyId };
  if (record.expiresAt.getTime() <= now.getTime()) return { kind: 'reject', reason: 'expired' };
  return { kind: 'rotate' };
}
