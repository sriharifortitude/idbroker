/** The /authorize query parameters, carried forward as hidden form
 *  fields across the login and consent steps rather than persisted
 *  server-side -- there is nothing here that is not already public in
 *  the original redirect URL, so a stateless round trip through the
 *  browser costs nothing extra and needs no cleanup job for abandoned
 *  attempts. */
export interface PendingRequest {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string | undefined;
  codeChallenge: string;
  nonce: string | undefined;
}
