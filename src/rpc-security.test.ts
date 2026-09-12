import assert from "node:assert/strict";
import test from "node:test";

import {
  redactRpcEndpoint,
  sanitizeRpcError
} from "./rpc-security.js";

test(
  "RPC redaction strips credentials",
  () => {
    const url =
      "https://alice:password@host.example/v2/SECRET?key=SECRET2";

    assert.equal(
      redactRpcEndpoint(url),
      "https://host.example"
    );

    const sanitized = sanitizeRpcError(
      new Error(`request to ${url} failed for SECRET and SECRET2`),
      [url]
    );

    assert.equal(sanitized.includes("password"), false);
    assert.equal(sanitized.includes("SECRET"), false);
    assert.equal(sanitized.includes("SECRET2"), false);
    assert.match(sanitized, /https:\/\/host\.example/);
  }
);
