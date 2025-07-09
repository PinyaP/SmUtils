export type ContractResultItem = {
  contractId: bigint;
  smartContractAddress: `0x${string}`;
  chainId: bigint;
  tokenAuthorityProvider: number;
  tokenAuthorityEndpoint: string;
  tokenAuthorityContractAddress: `0x${string}`;
  contractOwner: `0x${string}`;
  kernelIds: readonly bigint[];
  createdAt: bigint;
};

type Bytes32 = `0x${string & { length: 66 }}`;

export type DappResultItem = {
  dappId: bigint;
  contractId: bigint;
  entryId: Bytes32;
  dappOwner: `0x${string}`;
};
