export const RETENTION_DURATIONS = new Set([1, 7, 30, 90, 180]);
export const RETENTION_SCOPES = new Set(['chats', 'rooms']);
export function validateRetentionPolicy(input) {
  if (!input || !RETENTION_SCOPES.has(input.scope)) return { ok: false, error: 'Invalid conversation scope' };
  if (typeof input.conversationId !== 'string' || !/^[A-Za-z0-9_-]{8,80}$/.test(input.conversationId)) return { ok: false, error: 'Invalid conversation ID' };
  if (!['leave', 'timed'].includes(input.mode)) return { ok: false, error: 'Invalid retention mode' };
  if (input.mode === 'timed' && !RETENTION_DURATIONS.has(Number(input.days))) return { ok: false, error: 'Duration must be 1, 7, 30, 90 or 180 days' };
  return { ok: true, value: { scope: input.scope, conversationId: input.conversationId, mode: input.mode, days: input.mode === 'timed' ? Number(input.days) : null } };
}
export function expiryForPolicy(policy, now = new Date()) {
  if (!policy || policy.mode !== 'timed') return null;
  const expiry = new Date(now);
  expiry.setUTCDate(expiry.getUTCDate() + Number(policy.days));
  return expiry;
}
