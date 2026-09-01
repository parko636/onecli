import type { AppDefinition } from "./types";
import { OAUTH_STATE_SECRET, SECRET_ENCRYPTION_KEY } from "../lib/env";

// Remember The Milk's MCP OAuth server is spec-compliant (RFC 8414 metadata at
// https://www.rememberthemilk.com/.well-known/oauth-authorization-server) and
// supports Dynamic Client Registration (RFC 7591) plus public clients
// (token_endpoint_auth_methods_supported includes "none") and PKCE (S256).
// Registration is anonymous, so the resolver self-registers a client on the
// first connect (see the `dcr` field below and apps/dcr.ts) — no per-user app
// creation and no pre-provisioned env vars needed. Manual BYOC and the
// RTM_CLIENT_ID/RTM_CLIENT_SECRET env defaults still win when present.

const AUTHORIZE_URL = "https://www.rememberthemilk.com/oauth/authorize.rtm";
const TOKEN_URL = "https://www.rememberthemilk.com/oauth/token.rtm";
const REGISTRATION_URL = "https://www.rememberthemilk.com/oauth/register.rtm";
const INTROSPECTION_URL = "https://www.rememberthemilk.com/oauth/validate.rtm";

// Deterministic PKCE verifier derived from the signed OAuth state — same
// pattern as x.ts (no in-memory store; survives multi-instance deployments).
// node:crypto is imported lazily: this module rides the client-reachable app
// registry, whose graph must stay free of Node builtins.
const deriveCodeVerifier = async (state: string): Promise<string> => {
  const { createHmac } = await import("node:crypto");
  const key = OAUTH_STATE_SECRET || SECRET_ENCRYPTION_KEY;
  return createHmac("sha256", key)
    .update(`rtm-pkce:${state}`)
    .digest("base64url");
};

const deriveCodeChallenge = async (verifier: string): Promise<string> => {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(verifier).digest("base64url");
};

export const rememberTheMilk: AppDefinition = {
  id: "remember-the-milk",
  name: "Remember The Milk",
  icon: "/icons/remember-the-milk.png",
  description: "Tasks and lists in Remember The Milk.",
  connectionMethod: {
    type: "oauth",
    defaultScopes: ["read", "write"],
    permissions: [
      {
        scope: "read",
        name: "Read tasks",
        description: "Read tasks, lists, and notes",
        access: "read",
      },
      {
        scope: "write",
        name: "Manage tasks",
        description: "Create, edit, and complete tasks",
        access: "write",
      },
      {
        scope: "delete",
        name: "Delete tasks",
        description: "Permanently delete tasks and lists",
        access: "write",
      },
    ],
    buildAuthUrl: async ({ appCredentials, redirectUri, scopes, state }) => {
      if (!appCredentials.clientId) {
        // Unreachable when resolution succeeds — the DCR arm self-registers a
        // client — but kept as a guard for a hand-rolled empty config.
        throw new Error(
          "Remember The Milk client ID not configured — register one via " +
            `${REGISTRATION_URL} (RFC 7591 DCR) ` +
            "using this instance's redirect URI, then set RTM_CLIENT_ID.",
        );
      }
      const verifier = await deriveCodeVerifier(state);
      const challenge = await deriveCodeChallenge(verifier);
      const url = new URL(AUTHORIZE_URL);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", appCredentials.clientId);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("scope", scopes.join(" "));
      url.searchParams.set("state", state);
      url.searchParams.set("code_challenge", challenge);
      url.searchParams.set("code_challenge_method", "S256");
      return url.toString();
    },
    exchangeCode: async ({ appCredentials, callbackParams, redirectUri }) => {
      if (!callbackParams.code)
        throw new Error("RTM callback missing authorization code");
      if (!callbackParams.state)
        throw new Error("RTM callback missing state parameter");
      const codeVerifier = await deriveCodeVerifier(callbackParams.state);

      const body: Record<string, string> = {
        grant_type: "authorization_code",
        code: callbackParams.code,
        client_id: appCredentials.clientId!,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      };
      // Public client (DCR with no secret issued) vs confidential client —
      // RTM's server advertises both "none" and "client_secret_post".
      if (appCredentials.clientSecret)
        body.client_secret = appCredentials.clientSecret;

      const tokenRes = await fetch(TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(body),
      });

      if (!tokenRes.ok) {
        throw new Error(
          `RTM token exchange failed: ${tokenRes.status} ${tokenRes.statusText}`,
        );
      }

      const tokenData = (await tokenRes.json()) as {
        access_token?: string;
        refresh_token?: string;
        expires_in?: number;
        scope?: string;
        error?: string;
        error_description?: string;
      };

      if (tokenData.error || !tokenData.access_token) {
        throw new Error(
          tokenData.error_description ?? "Failed to exchange code for token",
        );
      }

      const credentials: Record<string, unknown> = {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        expires_at: tokenData.expires_in
          ? Math.floor(Date.now() / 1000) + tokenData.expires_in
          : undefined,
      };

      // RTM has no userinfo endpoint, but its RFC 7662 introspection response
      // carries the account identity (username, sub) — used as the connection
      // label and for same-account dedupe. Best-effort like todoist's user
      // fetch: a failure here costs only the label, never the connection.
      let metadata: Record<string, unknown> | undefined;
      try {
        const introspectRes = await fetch(INTROSPECTION_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            token: tokenData.access_token,
            client_id: appCredentials.clientId!,
            ...(appCredentials.clientSecret
              ? { client_secret: appCredentials.clientSecret }
              : {}),
          }),
        });
        if (introspectRes.ok) {
          const info = (await introspectRes.json()) as {
            username?: string;
            sub?: string;
          };
          if (info.username) {
            metadata = {
              username: info.username,
              ...(info.sub ? { accountId: info.sub } : {}),
            };
          }
        }
      } catch {
        // label-only — swallow
      }

      return {
        credentials,
        scopes: tokenData.scope?.split(" ").filter(Boolean) ?? [],
        metadata,
      };
    },
  },
  dcr: {
    registrationEndpoint: REGISTRATION_URL,
    clientName: "OneCLI",
  },
  configurable: {
    hint:
      "Optional — OneCLI self-registers a client via RTM's Dynamic Client " +
      "Registration on first connect. To bring your own instead, register at " +
      "https://www.rememberthemilk.com/oauth/register.rtm with this instance's " +
      "redirect URI and enter the issued credentials here.",
    fields: [
      {
        name: "clientId",
        label: "Client ID",
        placeholder: "issued by RTM's /oauth/register.rtm",
      },
      {
        name: "clientSecret",
        label: "Client Secret",
        placeholder: "(often none — public client)",
        secret: true,
      },
    ],
    envDefaults: {
      clientId: "RTM_CLIENT_ID",
      clientSecret: "RTM_CLIENT_SECRET",
    },
  },
};
