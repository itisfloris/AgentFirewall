import type {
  Provider,
  TransactionRequest
} from "ethers";

export interface TransactionSignerBoundary {
  readonly provider: Provider | null;
  getAddress(): Promise<string>;
  populateTransaction(
    request: TransactionRequest
  ): Promise<TransactionRequest>;
  signTransaction(
    request: TransactionRequest
  ): Promise<string>;
}

export class ExternalTransactionSignerAdapter
implements TransactionSignerBoundary {
  constructor(
    public readonly provider: Provider,
    private readonly address: string,
    private readonly populate: (
      request: TransactionRequest
    ) => Promise<TransactionRequest>,
    private readonly sign: (
      request: TransactionRequest
    ) => Promise<string>
  ) {}

  async getAddress(): Promise<string> {
    return this.address;
  }

  async populateTransaction(
    request: TransactionRequest
  ): Promise<TransactionRequest> {
    return this.populate(request);
  }

  async signTransaction(
    request: TransactionRequest
  ): Promise<string> {
    return this.sign(request);
  }
}
