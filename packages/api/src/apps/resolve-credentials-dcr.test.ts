import { beforeEach, describe, expect, it, vi } from "vitest";

// Pin the onprem edition before any import (lib/env captures env at first
// load): these tests exercise the workspace → env → DCR tiers with no org
// seam, matching the OSS default (resolve-credentials.test.ts precedent).
vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "onprem";
});

const WORKSPACE = "proj-1";
const REDIRECT_URI = "https://api.example.com/v1/apps/dcrapp/callback";
const ENV_VAR_ID = "DCR_TEST_CLIENT_ID";
const ENV_VAR_SECRET = "DCR_TEST_CLIENT_SECRET";

interface Row {
  id: string;
  workspaceId: string;
  provider: string;
  settings: Record<string, string>;
  credentials: string | null;
  enabled: boolean;
}

// In-memory AppConfig table. `create` does its duplicate check synchronously
// (no await before the insert), so it is atomic under interleaved async calls
// — exactly the unique-constraint semantics the concurrency test pins.
const store = vi.hoisted(() => ({
  rows: [] as Row[],
  seq: 0,
}));

vi.mock("@onecli/db", () => {
  class PrismaClientKnownRequestError extends Error {
    code: string;
    constructor(code: string) {
      super(code);
      this.code = code;
    }
  }
  return {
    Prisma: { PrismaClientKnownRequestError },
    db: {
      appConfig: {
        findUnique: async ({
          where,
        }: {
          where: {
            id?: string;
            workspaceId_provider?: { workspaceId: string; provider: string };
          };
        }) => {
          if (where.id)
            return store.rows.find((r) => r.id === where.id) ?? null;
          const key = where.workspaceId_provider!;
          return (
            store.rows.find(
              (r) =>
                r.workspaceId === key.workspaceId &&
                r.provider === key.provider,
            ) ?? null
          );
        },
        create: async ({ data }: { data: Omit<Row, "id"> }) => {
          if (
            store.rows.some(
              (r) =>
                r.workspaceId === data.workspaceId &&
                r.provider === data.provider,
            )
          ) {
            throw new PrismaClientKnownRequestError("P2002");
          }
          const row: Row = { ...data, id: `cfg-${++store.seq}` };
          store.rows.push(row);
          return { id: row.id };
        },
        update: async ({
          where,
          data,
        }: {
          where: { id: string };
          data: Partial<Row>;
        }) => {
          const row = store.rows.find((r) => r.id === where.id);
          if (!row) throw new Error("row not found");
          Object.assign(row, data);
          return { id: row.id };
        },
      },
    },
  };
});

import { resolveAppCredentials } from "./resolve-credentials";
import { initCrypto, initOrgAppConfig } from "../providers";
import type { AppDefinition } from "./types";

// Reversible fake so the service's encrypt-on-write / decrypt-on-read round
// trip is exercised without real key material.
initCrypto({
  encrypt: async (plaintext) => `enc:${plaintext}`,
  decrypt: async (encrypted) => encrypted.slice("enc:".length),
});

const app: AppDefinition = {
  id: "dcrapp",
  name: "DCR App",
  icon: "/icons/dcrapp.svg",
  description: "OAuth app with Dynamic Client Registration",
  connectionMethod: {
    type: "oauth",
    buildAuthUrl: () => "https://provider.example/auth",
    exchangeCode: async () => ({ credentials: {}, scopes: [] }),
  },
  dcr: {
    registrationEndpoint: "https://provider.example/oauth/register",
    clientName: "OneCLI",
  },
  configurable: {
    fields: [
      { name: "clientId", label: "Client ID", placeholder: "id" },
      {
        name: "clientSecret",
        label: "Client Secret",
        placeholder: "secret",
        secret: true,
      },
    ],
    envDefaults: { clientId: ENV_VAR_ID, clientSecret: ENV_VAR_SECRET },
  },
};

const registrationResponse = (n: number) => ({
  ok: true,
  status: 201,
  json: async () => ({
    client_id: `dcr-client-${n}`,
    client_secret: `dcr-secret-${n}`,
  }),
});

const mockRegistration = () => {
  let calls = 0;
  const fetchMock = vi.fn(async () => registrationResponse(++calls));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
};

const seedRow = (settings: Record<string, string>, clientSecret?: string) => {
  const row: Row = {
    id: `cfg-${++store.seq}`,
    workspaceId: WORKSPACE,
    provider: app.id,
    settings,
    credentials: clientSecret
      ? `enc:${JSON.stringify({ clientSecret })}`
      : null,
    enabled: true,
  };
  store.rows.push(row);
  return row;
};

describe("resolveAppCredentials — Dynamic Client Registration tier", () => {
  beforeEach(() => {
    initOrgAppConfig(null);
    store.rows = [];
    delete process.env[ENV_VAR_ID];
    delete process.env[ENV_VAR_SECRET];
    vi.unstubAllGlobals();
  });

  it("registers on the first resolve and persists the client as an AppConfig row", async () => {
    const fetchMock = mockRegistration();

    const resolved = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("https://provider.example/oauth/register");
    expect(JSON.parse(init.body as string)).toEqual({
      client_name: "OneCLI",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
    });

    expect(resolved).toEqual({
      values: { clientId: "dcr-client-1", clientSecret: "dcr-secret-1" },
      source: "app_config",
      appConfigId: "cfg-1",
    });

    expect(store.rows).toHaveLength(1);
    const row = store.rows[0]!;
    expect(row.enabled).toBe(true);
    expect(row.settings).toEqual({
      clientId: "dcr-client-1",
      dcrRedirectUri: REDIRECT_URI,
    });
    expect(row.credentials).toBe(
      `enc:${JSON.stringify({ clientSecret: "dcr-secret-1" })}`,
    );
  });

  it("reuses the stored client on the second resolve — no second registration", async () => {
    const fetchMock = mockRegistration();

    const first = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );
    const second = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(second).toEqual(first);
    expect(store.rows).toHaveLength(1);
  });

  it("env defaults win over registering a new client", async () => {
    const fetchMock = mockRegistration();
    process.env[ENV_VAR_ID] = "env-id";
    process.env[ENV_VAR_SECRET] = "env-secret";

    const resolved = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );

    expect(resolved).toEqual({
      values: { clientId: "env-id", clientSecret: "env-secret" },
      source: "env",
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(store.rows).toHaveLength(0);
  });

  it("a manual BYOC row (no DCR marker) wins and is never drift-checked", async () => {
    const fetchMock = mockRegistration();
    const row = seedRow({ clientId: "byoc-id" }, "byoc-secret");

    const resolved = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );

    expect(resolved).toEqual({
      values: { clientId: "byoc-id", clientSecret: "byoc-secret" },
      source: "app_config",
      appConfigId: row.id,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("redirect-URI drift re-registers and replaces the row in place", async () => {
    const fetchMock = mockRegistration();
    const row = seedRow(
      { clientId: "old-client", dcrRedirectUri: "http://old.example/cb" },
      "old-secret",
    );

    const resolved = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(resolved).toEqual({
      values: { clientId: "dcr-client-1", clientSecret: "dcr-secret-1" },
      source: "app_config",
      appConfigId: row.id, // same row — provenance links survive
    });
    expect(store.rows).toHaveLength(1);
    expect(row.settings).toEqual({
      clientId: "dcr-client-1",
      dcrRedirectUri: REDIRECT_URI,
    });
  });

  it("a matching redirect URI is not drift — no re-registration", async () => {
    const fetchMock = mockRegistration();
    const row = seedRow(
      { clientId: "stored-client", dcrRedirectUri: REDIRECT_URI },
      "stored-secret",
    );

    const resolved = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );

    expect(resolved?.appConfigId).toBe(row.id);
    expect(resolved?.values.clientId).toBe("stored-client");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("falls back to the stored client when drift re-registration fails", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 503,
      json: async () => ({}),
    }));
    vi.stubGlobal("fetch", fetchMock);
    seedRow(
      { clientId: "old-client", dcrRedirectUri: "http://old.example/cb" },
      "old-secret",
    );

    const resolved = await resolveAppCredentials(
      WORKSPACE,
      app,
      undefined,
      REDIRECT_URI,
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(resolved?.values).toEqual({
      clientId: "old-client",
      clientSecret: "old-secret",
    });
  });

  it("concurrent first resolves create exactly one row and converge on one client", async () => {
    const fetchMock = mockRegistration();

    const [a, b] = await Promise.all([
      resolveAppCredentials(WORKSPACE, app, undefined, REDIRECT_URI),
      resolveAppCredentials(WORKSPACE, app, undefined, REDIRECT_URI),
    ]);

    // Both registered (the race is real), but only one create landed and the
    // loser re-read the winner's row instead of clobbering it.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(store.rows).toHaveLength(1);
    const stored = store.rows[0]!;
    expect(a?.appConfigId).toBe(stored.id);
    expect(b?.appConfigId).toBe(stored.id);
    expect(a?.values.clientId).toBe(stored.settings.clientId);
    expect(b?.values.clientId).toBe(stored.settings.clientId);
  });

  it("never registers without a redirect URI (refresh-path callers)", async () => {
    const fetchMock = mockRegistration();

    expect(await resolveAppCredentials(WORKSPACE, app)).toBeNull();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(store.rows).toHaveLength(0);
  });

  it("returns null when registration fails on first connect", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: "invalid_client_metadata" }),
    }));
    vi.stubGlobal("fetch", fetchMock);

    expect(
      await resolveAppCredentials(WORKSPACE, app, undefined, REDIRECT_URI),
    ).toBeNull();
    expect(store.rows).toHaveLength(0);
  });
});
