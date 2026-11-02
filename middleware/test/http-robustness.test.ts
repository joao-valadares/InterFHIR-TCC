import { expect } from "chai";
import { createHttpServer } from "../src/api/http-server.js";
import type { AddressInfo } from "node:net";
describe("HTTP request failure containment", function () {
  it("returns safe errors and continues serving after invalid, oversized and rejected requests", async function () {
    const server = createHttpServer({ handle: async request => {
      if (request.path === "/fail") throw new Error("private dependency payload");
      return { status: 200, body: { ok: true } };
    } });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const base = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
    try {
      for (const [route, body, status, error] of [["/", "{", 400, "INVALID_JSON"], ["/", "x".repeat(1048577), 413, "REQUEST_BODY_TOO_LARGE"], ["/fail", "{}", 500, "INTERNAL_SERVER_ERROR"]] as const) {
        const response = await fetch(base + route, { method: "POST", body });
        expect(response.status).to.equal(status);
        expect(await response.json()).to.deep.equal({ error });
      }
      expect((await fetch(base)).status).to.equal(200);
    } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  });
});
