import { logger } from "../lib/logger";
import type { AppDefinition } from "./types";

export interface DcrRegisteredClient {
  clientId: string;
  clientSecret: string;
}

/**
 * Register an OAuth client at a provider's RFC 7591 registration endpoint.
 *
 * Requests a confidential client (`client_secret_post`) with the refresh_token
 * grant so the gateway's refresh path has a secret to present, bound to this
 * instance's redirect URI. Returns null on any failure — registration is a
 * best-effort convenience tier, and the caller degrades to "not configured"
 * (first connect) or the stored client (drift re-registration).
 */
export const registerDcrClient = async (
  dcr: NonNullable<AppDefinition["dcr"]>,
  redirectUri: string,
): Promise<DcrRegisteredClient | null> => {
  let data: { client_id?: string; client_secret?: string };
  try {
    const res = await fetch(dcr.registrationEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: dcr.clientName,
        redirect_uris: [redirectUri],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      logger.warn(
        { status: res.status, endpoint: dcr.registrationEndpoint },
        "dynamic client registration rejected",
      );
      return null;
    }
    data = (await res.json()) as typeof data;
  } catch (err) {
    logger.warn(
      { err, endpoint: dcr.registrationEndpoint },
      "dynamic client registration request failed",
    );
    return null;
  }

  // client_secret is required, not optional: the registration asked for
  // client_secret_post, and downstream (the resolver's completeness check,
  // the gateway's refresh) treats the secret as part of the client.
  if (!data.client_id || !data.client_secret) {
    logger.warn(
      { endpoint: dcr.registrationEndpoint },
      "dynamic client registration response missing client_id/client_secret",
    );
    return null;
  }

  return { clientId: data.client_id, clientSecret: data.client_secret };
};
