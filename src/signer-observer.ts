import type {
  Signer,
  TransactionRequest
} from "ethers";

export function observeSigner(
  signer: Signer
): {
  signer: Signer;
  signTransactionCalls: () => number;
} {
  let signTransactionCalls = 0;

  const observed = new Proxy(
    signer as Signer & Record<PropertyKey, unknown>,
    {
      get(target, property) {
        if (property === "signTransaction") {
          return async (transaction: TransactionRequest) => {
            signTransactionCalls += 1;
            return target.signTransaction(transaction);
          };
        }

        const value = Reflect.get(
          target,
          property,
          target
        );

        return typeof value === "function"
          ? value.bind(target)
          : value;
      }
    }
  ) as Signer;

  return {
    signer: observed,
    signTransactionCalls: () => signTransactionCalls
  };
}
