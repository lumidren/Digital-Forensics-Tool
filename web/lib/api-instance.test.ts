import { describe, expect, it, vi } from "vitest";
import { api } from "./api-instance";
import { getToken, setToken } from "./token-store";

describe("api instance", () => {
  it("uses the configured base URL and ends the session on 401", async () => {
    expect(api.baseUrl).toBe("http://localhost:8000");
    setToken("tok", 60);
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({ detail: "expired" }), { status: 401 }))),
    );
    await expect(api.me()).rejects.toMatchObject({ status: 401 });
    expect(getToken()).toBeNull();
    vi.unstubAllGlobals();
  });
});
