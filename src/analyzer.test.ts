import test from "node:test";
import assert from "node:assert/strict";

import {
  Interface,
  MaxUint256
} from "ethers";

import {
  analyzeTransaction
} from "./analyzer.js";

test(
  "blocks unlimited ERC-20 approvals",
  () => {
    const iface = new Interface([
      "function approve(address spender,uint256 amount)"
    ]);

    const result =
      analyzeTransaction({
        to:
          "0x2222222222222222222222222222222222222222",

        data:
          iface.encodeFunctionData(
            "approve",
            [
              "0x1111111111111111111111111111111111111111",
              MaxUint256
            ]
          )
      });

    assert.equal(
      result.decision,
      "BLOCK"
    );

    assert.equal(
      result.risk,
      "critical"
    );

    assert.ok(
      result.findings.some(
        finding =>
          finding.code ===
          "UNLIMITED_APPROVAL"
      )
    );
  }
);

test(
  "allows native transfer below policy limit",
  () => {
    const result =
      analyzeTransaction(
        {
          to:
            "0x3333333333333333333333333333333333333333",

          data: "0x",

          valueWei:
            "1000000000000000"
        },
        {
          maxNativeValueWei:
            "5000000000000000"
        }
      );

    assert.equal(
      result.decision,
      "ALLOW"
    );
  }
);

test(
  "blocks native transfer above policy limit",
  () => {
    const result =
      analyzeTransaction(
        {
          to:
            "0x3333333333333333333333333333333333333333",

          data: "0x",

          valueWei:
            "9000000000000000"
        },
        {
          maxNativeValueWei:
            "5000000000000000"
        }
      );

    assert.equal(
      result.decision,
      "BLOCK"
    );

    assert.ok(
      result.findings.some(
        finding =>
          finding.code ===
          "SPENDING_LIMIT_EXCEEDED"
      )
    );
  }
);

test(
  "strict policy blocks unknown calldata",
  () => {
    const result =
      analyzeTransaction(
        {
          to:
            "0x4444444444444444444444444444444444444444",

          data:
            "0x12345678"
        },
        {
          requireKnownCalldata:
            true
        }
      );

    assert.equal(
      result.decision,
      "BLOCK"
    );

    assert.ok(
      result.findings.some(
        finding =>
          finding.code ===
          "UNKNOWN_CALLDATA"
      )
    );
  }
);
