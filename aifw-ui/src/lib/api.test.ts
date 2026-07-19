import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api } from "./api";

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, String(value)); },
  };
}

describe("API client", () => {
  beforeEach(() => {
    const storage = memoryStorage();
    vi.stubGlobal("localStorage", storage);
    vi.stubGlobal("window", { localStorage: storage });
  });

  it("serializes JSON and sends the stored bearer token", async () => {
    localStorage.setItem("aifw_token", "test-token");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ saved: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(api.post("/api/v1/example", { enabled: true })).resolves.toEqual({ saved: true });
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/example", {
      method: "POST",
      headers: {
        Authorization: "Bearer test-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ enabled: true }),
      signal: undefined,
    });
  });

  it("surfaces the API's JSON error message and status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "rule already exists" }), {
          status: 409,
          statusText: "Conflict",
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    const request = api.post("/api/v1/rules", { label: "duplicate" }, { noAuthRedirect: true });
    await expect(request).rejects.toMatchObject<ApiError>({
      name: "ApiError",
      status: 409,
      message: "rule already exists",
    });
  });

  it("does not clear credentials when login itself returns unauthorized", async () => {
    localStorage.setItem("aifw_token", "existing-token");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("bad credentials", { status: 401, statusText: "Unauthorized" }),
      ),
    );

    await expect(
      api.post("/api/v1/auth/login", { username: "admin", password: "wrong" }, { noAuthRedirect: true }),
    ).rejects.toMatchObject({ status: 401, message: "bad credentials" });
    expect(localStorage.getItem("aifw_token")).toBe("existing-token");
  });

  it("accepts an empty successful response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));

    await expect(api.delete("/api/v1/rules/example")).resolves.toBeUndefined();
  });
});
