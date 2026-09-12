import assert from "node:assert/strict";
import test from "node:test";
import {
  createServer,
  type RequestListener,
  type Server
} from "node:http";

import {
  AgentFirewallClient
} from "./sdk.js";

async function withServer(
  handler: RequestListener,
  run: (baseUrl: string) => Promise<void>
): Promise<void> {
  const server: Server = createServer(handler);

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  try {
    const address = server.address();

    if (!address || typeof address === "string") {
      throw new Error("Unable to resolve test server address");
    }

    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>(resolve => {
      server.close(() => resolve());
      server.closeAllConnections?.();
    });
  }
}

test(
  "client rejects malformed ALLOW",
  async () => {
    await withServer(
      (_request, response) => {
        response.writeHead(200, {
          "Content-Type": "application/json"
        });
        response.end(JSON.stringify({
          decision: "ALLOW"
        }));
      },
      async baseUrl => {
        const client = new AgentFirewallClient(baseUrl, 1000);

        await assert.rejects(
          () => client.preflight({
            chain: "ethereum",
            to: "0x1111111111111111111111111111111111111111",
            valueWei: "0",
            data: "0x"
          }),
          /malformed response/
        );
      }
    );
  }
);

test(
  "client times out stalled responses",
  async () => {
    await withServer(
      (_request, response) => {
        const timer = setTimeout(() => {
          if (!response.destroyed) {
            response.writeHead(200, {
              "Content-Type": "application/json"
            });
            response.end("{}");
          }
        }, 1000);
        timer.unref();
      },
      async baseUrl => {
        const client = new AgentFirewallClient(baseUrl, 100);

        await assert.rejects(
          () => client.preflight({
            chain: "ethereum",
            to: "0x1111111111111111111111111111111111111111",
            valueWei: "0",
            data: "0x"
          }),
          /timed out/
        );
      }
    );
  }
);

test(
  "HTTP guard rejects remote http",
  async () => {
    const client =
      new AgentFirewallClient(
        "http://example.invalid",
        1000
      );

    await assert.rejects(
      () => client.guard({
        chain: "ethereum",
        to: "0x1111111111111111111111111111111111111111",
        valueWei: "0",
        data: "0x"
      }),
      /must use HTTPS/
    );
  }
);


test(
  "client rejects oversized responses",
  async () => {
    await withServer(
      (_request, response) => {
        response.writeHead(200, {
          "Content-Type": "application/json"
        });
        response.end(JSON.stringify({
          padding: "x".repeat(524289)
        }));
      },
      async baseUrl => {
        const client = new AgentFirewallClient(baseUrl, 1000);

        await assert.rejects(
          () => client.preflight({
            chain: "ethereum",
            to: "0x1111111111111111111111111111111111111111",
            valueWei: "0",
            data: "0x"
          }),
          /512 KiB client safety bound/
        );
      }
    );
  }
);
