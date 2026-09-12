import { getAddress } from "ethers";

import {
  GuardedSignerRejectedError
} from "./guarded-signer-error.js";

const reservations = new Set<string>();

function reservationKey(
  chainId: bigint,
  sender: string,
  nonce: number
): string {
  return `${chainId.toString()}:${getAddress(sender).toLowerCase()}:${nonce}`;
}

export function reserveExecutionNonce(
  chainId: bigint,
  sender: string,
  nonce: number
): () => void {
  const key = reservationKey(
    chainId,
    sender,
    nonce
  );

  if (reservations.has(key)) {
    throw new GuardedSignerRejectedError(
      `nonce ${nonce} is already reserved for this sender and chain`,
      "NONCE_ALREADY_RESERVED"
    );
  }

  reservations.add(key);
  let released = false;

  return () => {
    if (!released) {
      reservations.delete(key);
      released = true;
    }
  };
}
