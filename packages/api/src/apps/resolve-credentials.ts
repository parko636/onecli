import {
  getAppConfigCredentials,
  createDcrAppConfig,
  updateDcrAppConfig,
} from "../services/app-config-service";
import { getOrgAppConfig } from "../providers";
import { registerDcrClient, type DcrRegisteredClient } from "./dcr";
import type { AppDefinition } from "./types";

export interface ResolvedAppCredentials {
  values: Record<string, string>;
  source: "app_config" | "env";
  /**
   * Id of the AppConfig row that served these credentials (the workspace row or,
   * via the org seam, the org row). Absent for the env tier. Mint sites persist
   * it on the connection so refresh and config-removal know the provenance.
   */
  appConfigId?: string;
}

const pickRequired = (
  requiredFields: string[],
  fields: Record<string, string>,
): Record<string, string> => {
  const values: Record<string, string> = {};
  for (const f of requiredFields) values[f] = fields[f]!;
  return values;
};

const dcrValues = (client: DcrRegisteredClient): Record<string, string> => ({
  clientId: client.clientId,
  clientSecret: client.clientSecret,
});

/**
 * Generic credential resolution for any configurable app.
 * Uses the app's `configurable.fields` to determine which keys are needed,
 * then resolves them from AppConfig (user-provided) → the organization's
 * AppConfig (EE editions with the `orgAppConfig` seam registered; skipped in
 * OSS) → env vars (platform defaults) → Dynamic Client Registration (apps
 * declaring `dcr`, connect paths only) → null.
 *
 * Works for all method types: OAuth (clientId/clientSecret), GitHub App (appId/appSlug/privateKey),
 * and any future configurable provider.
 *
 * `redirectUri` is the OAuth redirect URI the caller is about to hand the
 * provider — only the connect routes have one (derived via
 * `getApiCallbackOrigin`, see routes/apps.ts). It gates the DCR tier: a
 * registration is only useful bound to a redirect URI, so paths without one
 * (refresh, availability checks) never register and never drift-check.
 */
export const resolveAppCredentials = async (
  workspaceId: string,
  app: AppDefinition,
  organizationId?: string,
  redirectUri?: string,
): Promise<ResolvedAppCredentials | null> => {
  if (!app.configurable) return null;

  const requiredFields = app.configurable.fields.map((f) => f.name);

  const config = await getAppConfigCredentials({ workspaceId }, app.id);
  if (config && requiredFields.every((f) => !!config.fields[f])) {
    // The `dcrRedirectUri` marker means this resolver registered the row
    // itself (manual BYOC rows never carry it and are never touched). If the
    // instance's redirect URI has drifted from the one registered with the
    // provider, the stored client is useless — the provider rejects the URI —
    // so re-register and replace the row in place. Connections minted under
    // the old client keep their provenance link; their refresh tokens die
    // with the old client, which a URL move breaks regardless.
    const registeredUri = config.fields.dcrRedirectUri;
    if (
      app.dcr &&
      redirectUri &&
      registeredUri &&
      registeredUri !== redirectUri
    ) {
      const reRegistered = await registerDcrClient(app.dcr, redirectUri);
      if (reRegistered) {
        await updateDcrAppConfig(config.appConfigId, {
          ...reRegistered,
          redirectUri,
        });
        return {
          values: dcrValues(reRegistered),
          source: "app_config",
          appConfigId: config.appConfigId,
        };
      }
      // Re-registration failed (already logged): fall through to the stored
      // client so a transient registration outage degrades to the provider's
      // own redirect-URI error instead of "not configured".
    }
    return {
      values: pickRequired(requiredFields, config.fields),
      source: "app_config",
      appConfigId: config.appConfigId,
    };
  }

  const orgAppConfig = getOrgAppConfig();
  if (orgAppConfig && organizationId) {
    const resolved = await orgAppConfig.resolveCredentials(organizationId, app);
    if (resolved) return resolved;
  }

  const envDefaults = app.configurable.envDefaults ?? {};
  const envValues: Record<string, string> = {};
  let envComplete = true;
  for (const field of requiredFields) {
    const envVar = envDefaults[field];
    const value = envVar ? process.env[envVar] : undefined;
    if (!value) {
      envComplete = false;
      break;
    }
    envValues[field] = value;
  }
  if (envComplete) return { values: envValues, source: "env" };

  // Last tier: self-register a client via RFC 7591 Dynamic Client Registration.
  if (app.dcr && redirectUri) {
    const registered = await registerDcrClient(app.dcr, redirectUri);
    if (!registered) return null;

    const created = await createDcrAppConfig({ workspaceId }, app.id, {
      ...registered,
      redirectUri,
    });
    if (created) {
      return {
        values: dcrValues(registered),
        source: "app_config",
        appConfigId: created.id,
      };
    }

    // Unique-key conflict: a concurrent first connect won the create race (or
    // a disabled/incomplete row already occupies the slot). Discard the client
    // just registered and reuse the stored one — both legs of every in-flight
    // flow must present the client_id the row serves.
    const existing = await getAppConfigCredentials({ workspaceId }, app.id);
    if (existing && requiredFields.every((f) => !!existing.fields[f])) {
      return {
        values: pickRequired(requiredFields, existing.fields),
        source: "app_config",
        appConfigId: existing.appConfigId,
      };
    }
    // A disabled or hand-half-filled row holds the slot: an admin's explicit
    // state — don't resurrect or overwrite it.
    return null;
  }

  return null;
};
