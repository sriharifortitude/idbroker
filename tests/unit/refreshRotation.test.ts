import { describe, expect, it } from 'vitest';
import { decideRotation, type RefreshTokenRecord } from '@/core/refreshRotation';

const now = new Date('2026-01-15T12:00:00Z');

function record(overrides: Partial<RefreshTokenRecord> = {}): RefreshTokenRecord {
  return {
    familyId: 'family-1',
    replacedByHash: null,
    revokedAt: null,
    expiresAt: new Date('2026-02-01T00:00:00Z'),
    ...overrides,
  };
}

describe('decideRotation', () => {
  it('rotates a fresh, unexpired, unused token', () => {
    expect(decideRotation(record(), now)).toEqual({ kind: 'rotate' });
  });

  it('rejects a token that does not exist', () => {
    expect(decideRotation(null, now)).toEqual({ kind: 'reject', reason: 'not_found' });
  });

  it('rejects an explicitly revoked token', () => {
    const r = record({ revokedAt: new Date('2026-01-10T00:00:00Z') });
    expect(decideRotation(r, now)).toEqual({ kind: 'reject', reason: 'revoked' });
  });

  it('rejects an expired token', () => {
    const r = record({ expiresAt: new Date('2026-01-01T00:00:00Z') });
    expect(decideRotation(r, now)).toEqual({ kind: 'reject', reason: 'expired' });
  });

  it('treats the exact expiry instant as already expired', () => {
    const r = record({ expiresAt: now });
    expect(decideRotation(r, now)).toEqual({ kind: 'reject', reason: 'expired' });
  });

  it('detects reuse when a token that was already rotated away is presented again', () => {
    const r = record({ replacedByHash: 'some-other-token-hash' });
    expect(decideRotation(r, now)).toEqual({ kind: 'reuse_detected', familyId: 'family-1' });
  });

  it('detects reuse even if the reused token has since also expired', () => {
    // A token stolen long ago and only just replayed: still a theft
    // signal, and the family still needs revoking, regardless of
    // whether the specific stolen copy would also fail on expiry alone.
    const r = record({ replacedByHash: 'some-other-token-hash', expiresAt: new Date('2020-01-01T00:00:00Z') });
    expect(decideRotation(r, now)).toEqual({ kind: 'reuse_detected', familyId: 'family-1' });
  });

  it('checks revocation before reuse: a revoked family reports revoked, not reuse', () => {
    const r = record({ replacedByHash: 'some-other-token-hash', revokedAt: new Date('2026-01-10T00:00:00Z') });
    expect(decideRotation(r, now)).toEqual({ kind: 'reject', reason: 'revoked' });
  });
});
