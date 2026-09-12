import type {
  runVerifiedPreflight
} from "./verified-preflight.js";

export class GuardedSignerRejectedError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly verdict?: Awaited<ReturnType<typeof runVerifiedPreflight>>
  ) {
    super(message);
    this.name = "GuardedSignerRejectedError";
  }
}
