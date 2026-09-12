import test from "node:test";
import assert from "node:assert/strict";

import {
  Interface,
  MaxUint256
} from "ethers";

import {
  declaredIntentSchema,
  decodeActualEffect,
  matchDeclaredIntent,
  type DeclaredIntent
} from "./intent.js";

const TOKEN =
  "0x2222222222222222222222222222222222222222";
const OTHER_TOKEN =
  "0x9999999999999999999999999999999999999999";
const SENDER =
  "0x5555555555555555555555555555555555555555";
const SPENDER =
  "0x1111111111111111111111111111111111111111";
const OTHER =
  "0x3333333333333333333333333333333333333333";
const RECIPIENT =
  "0x4444444444444444444444444444444444444444";
const OWNER =
  "0x6666666666666666666666666666666666666666";

const iface = new Interface([
  "function approve(address spender,uint256 amount)",
  "function transfer(address to,uint256 amount)",
  "function transferFrom(address from,address to,uint256 amount)",
  "function setApprovalForAll(address operator,bool approved)"
]);

function approveTx(
  amount = 1n,
  spender = SPENDER,
  target = TOKEN
) {
  return {
    chain: "ethereum",
    from: SENDER,
    to: target,
    data:
      iface.encodeFunctionData(
        "approve",
        [spender, amount]
      ),
    valueWei: "0"
  };
}

function approveIntent(
  overrides: Partial<Extract<DeclaredIntent, { action: "erc20_approve" }>> = {}
): Extract<DeclaredIntent, { action: "erc20_approve" }> {
  return {
    executionChainId: "1",
    sender: SENDER,
    action: "erc20_approve",
    target: TOKEN,
    asset: {
      kind: "erc20",
      address: TOKEN
    },
    spender: SPENDER,
    amountRaw: "1",
    method: "approve(address,uint256)",
    ...overrides
  };
}

function codes(
  declared: DeclaredIntent,
  actual = decodeActualEffect(approveTx())
) {
  return matchDeclaredIntent(
    declared,
    actual
  ).findings.map(
    finding => finding.code
  );
}

test(
  "ERC-20 approval matches",
  () => {
    const result =
      matchDeclaredIntent(
        approveIntent(),
        decodeActualEffect(approveTx())
      );

    assert.equal(result.ok, true);
    assert.equal(result.decision, "ALLOW");
  }
);

test(
  "amount mutation blocks",
  () => {
    const actual =
      decodeActualEffect(
        approveTx(MaxUint256)
      );

    assert.ok(
      codes(approveIntent(), actual)
        .includes("AMOUNT_MISMATCH")
    );
  }
);

test(
  "spender mutation blocks",
  () => {
    assert.ok(
      codes(
        approveIntent(),
        decodeActualEffect(
          approveTx(1n, OTHER)
        )
      ).includes("SPENDER_MISMATCH")
    );
  }
);

test(
  "target mutation blocks",
  () => {
    const result =
      codes(
        approveIntent(),
        decodeActualEffect(
          approveTx(1n, SPENDER, OTHER_TOKEN)
        )
      );

    assert.ok(result.includes("TARGET_MISMATCH"));
    assert.ok(result.includes("ASSET_MISMATCH"));
  }
);

test(
  "chain mismatch blocks",
  () => {
    assert.ok(
      codes(
        approveIntent({
          executionChainId: "11155111"
        })
      ).includes("CHAIN_MISMATCH")
    );
  }
);

test(
  "sender mismatch blocks",
  () => {
    assert.ok(
      codes(
        approveIntent({
          sender: OTHER
        })
      ).includes("SENDER_MISMATCH")
    );
  }
);

test(
  "missing constrained sender blocks",
  () => {
    const { from: _from, ...tx } = approveTx();

    assert.ok(
      codes(
        approveIntent(),
        decodeActualEffect(tx)
      ).includes("SENDER_MISSING")
    );
  }
);

test(
  "method mismatch blocks",
  () => {
    assert.ok(
      codes(
        approveIntent({
          method: "transfer(address,uint256)"
        })
      ).includes("METHOD_MISMATCH")
    );
  }
);

test(
  "unknown calldata blocks",
  () => {
    const actual =
      decodeActualEffect({
        chain: "ethereum",
        from: SENDER,
        to: TOKEN,
        data: "0x12345678",
        valueWei: "0"
      });

    const result =
      matchDeclaredIntent(
        approveIntent(),
        actual
      );

    assert.equal(result.decision, "BLOCK");
    assert.ok(
      result.findings.some(
        finding =>
          finding.code === "UNKNOWN_ACTUAL_EFFECT"
      )
    );
  }
);

test(
  "empty zero-value tx is blocked",
  () => {
    const actual =
      decodeActualEffect({
        chain: "ethereum",
        from: SENDER,
        to: TOKEN,
        data: "0x",
        valueWei: "0"
      });

    assert.equal(actual.kind, "unknown");
  }
);

test(
  "ERC-20 transfer matches",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      sender: SENDER,
      action: "erc20_transfer",
      target: TOKEN,
      asset: {
        kind: "erc20",
        address: TOKEN
      },
      recipient: RECIPIENT,
      amountRaw: "7"
    };

    const actual =
      decodeActualEffect({
        chain: "ethereum",
        from: SENDER,
        to: TOKEN,
        data:
          iface.encodeFunctionData(
            "transfer",
            [RECIPIENT, 7n]
          )
      });

    assert.equal(
      matchDeclaredIntent(declared, actual).ok,
      true
    );
  }
);

test(
  "ERC-20 transfer recipient mutation blocks",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "erc20_transfer",
      target: TOKEN,
      asset: {
        kind: "erc20",
        address: TOKEN
      },
      recipient: RECIPIENT,
      amountRaw: "7"
    };

    const actual =
      decodeActualEffect({
        to: TOKEN,
        data:
          iface.encodeFunctionData(
            "transfer",
            [OTHER, 7n]
          )
      });

    assert.ok(
      matchDeclaredIntent(declared, actual)
        .findings.some(
          finding =>
            finding.code === "RECIPIENT_MISMATCH"
        )
    );
  }
);

test(
  "transferFrom matches",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "erc20_transfer_from",
      target: TOKEN,
      asset: {
        kind: "erc20",
        address: TOKEN
      },
      owner: OWNER,
      recipient: RECIPIENT,
      amountRaw: "9"
    };

    const actual =
      decodeActualEffect({
        to: TOKEN,
        data:
          iface.encodeFunctionData(
            "transferFrom",
            [OWNER, RECIPIENT, 9n]
          )
      });

    assert.equal(
      matchDeclaredIntent(declared, actual).ok,
      true
    );
  }
);

test(
  "transferFrom owner mutation blocks",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "erc20_transfer_from",
      target: TOKEN,
      asset: {
        kind: "erc20",
        address: TOKEN
      },
      owner: OWNER,
      recipient: RECIPIENT,
      amountRaw: "9"
    };

    const actual =
      decodeActualEffect({
        to: TOKEN,
        data:
          iface.encodeFunctionData(
            "transferFrom",
            [OTHER, RECIPIENT, 9n]
          )
      });

    assert.ok(
      matchDeclaredIntent(declared, actual)
        .findings.some(
          finding =>
            finding.code === "OWNER_MISMATCH"
        )
    );
  }
);

test(
  "NFT operator approval matches",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "nft_set_approval_for_all",
      target: TOKEN,
      asset: {
        kind: "nft",
        address: TOKEN
      },
      operator: SPENDER,
      approved: true
    };

    const actual =
      decodeActualEffect({
        to: TOKEN,
        data:
          iface.encodeFunctionData(
            "setApprovalForAll",
            [SPENDER, true]
          )
      });

    assert.equal(
      matchDeclaredIntent(declared, actual).ok,
      true
    );
  }
);

test(
  "NFT operator mutation blocks",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "nft_set_approval_for_all",
      target: TOKEN,
      asset: {
        kind: "nft",
        address: TOKEN
      },
      operator: SPENDER,
      approved: true
    };

    const actual =
      decodeActualEffect({
        to: TOKEN,
        data:
          iface.encodeFunctionData(
            "setApprovalForAll",
            [OTHER, true]
          )
      });

    assert.ok(
      matchDeclaredIntent(declared, actual)
        .findings.some(
          finding =>
            finding.code === "OPERATOR_MISMATCH"
        )
    );
  }
);

test(
  "NFT approval flag mutation blocks",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "nft_set_approval_for_all",
      target: TOKEN,
      asset: {
        kind: "nft",
        address: TOKEN
      },
      operator: SPENDER,
      approved: true
    };

    const actual =
      decodeActualEffect({
        to: TOKEN,
        data:
          iface.encodeFunctionData(
            "setApprovalForAll",
            [SPENDER, false]
          )
      });

    assert.ok(
      matchDeclaredIntent(declared, actual)
        .findings.some(
          finding =>
            finding.code === "APPROVAL_FLAG_MISMATCH"
        )
    );
  }
);

test(
  "native transfer matches",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "native_transfer",
      target: RECIPIENT,
      asset: {
        kind: "native"
      },
      recipient: RECIPIENT,
      amountRaw: "123"
    };

    const actual =
      decodeActualEffect({
        to: RECIPIENT,
        data: "0x",
        valueWei: "123"
      });

    assert.equal(
      matchDeclaredIntent(declared, actual).ok,
      true
    );
  }
);

test(
  "native amount mutation blocks",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "native_transfer",
      target: RECIPIENT,
      asset: {
        kind: "native"
      },
      recipient: RECIPIENT,
      amountRaw: "123"
    };

    const actual =
      decodeActualEffect({
        to: RECIPIENT,
        data: "0x",
        valueWei: "124"
      });

    assert.ok(
      matchDeclaredIntent(declared, actual)
        .findings.some(
          finding =>
            finding.code === "AMOUNT_MISMATCH"
        )
    );
  }
);

test(
  "action mutation blocks before argument matching",
  () => {
    const declared: DeclaredIntent = {
      executionChainId: "1",
      action: "erc20_transfer",
      target: TOKEN,
      asset: {
        kind: "erc20",
        address: TOKEN
      },
      recipient: RECIPIENT,
      amountRaw: "1"
    };

    const result =
      matchDeclaredIntent(
        declared,
        decodeActualEffect(approveTx())
      );

    assert.ok(
      result.findings.some(
        finding =>
          finding.code === "ACTION_MISMATCH"
      )
    );
  }
);

test(
  "unknown chain label is rejected",
  () => {
    assert.throws(
      () =>
        decodeActualEffect({
          chain: "polygon",
          to: TOKEN,
          data: "0x",
          valueWei: "1"
        }),
      /unsupported chain/
    );
  }
);

test(
  "non-integer value is rejected",
  () => {
    assert.throws(
      () =>
        decodeActualEffect({
          to: TOKEN,
          valueWei: "1.5"
        }),
      /unsigned integer/
    );
  }
);

test(
  "ERC-20 action with native value blocks",
  () => {
    const actual =
      decodeActualEffect({
        ...approveTx(),
        valueWei: "1"
      });

    assert.ok(
      matchDeclaredIntent(
        approveIntent(),
        actual
      ).findings.some(
        finding =>
          finding.code === "UNEXPECTED_NATIVE_VALUE"
      )
    );
  }
);

test(
  "trailing calldata blocks",
  () => {
    const canonical =
      approveTx().data;

    const actual =
      decodeActualEffect({
        ...approveTx(),
        data: `${canonical}00`
      });

    assert.equal(actual.kind, "unknown");

    const result =
      matchDeclaredIntent(
        approveIntent(),
        actual
      );

    assert.ok(
      result.findings.some(
        finding =>
          finding.code === "UNKNOWN_ACTUAL_EFFECT"
      )
    );
  }
);


test(
  "declared intent rejects extra fields",
  () => {
    const parsed = declaredIntentSchema.safeParse({
      ...approveIntent(),
      unexpectedAuthorizationMeaning: "do-not-ignore"
    });

    assert.equal(parsed.success, false);
  }
);
