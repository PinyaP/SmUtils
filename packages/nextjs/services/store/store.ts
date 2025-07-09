import { create } from "zustand";
import scaffoldConfig from "~~/scaffold.config";
import { ChainWithAttributes } from "~~/utils/scaffold-eth";

/**
 * Zustand Store
 *
 * You can add global state to the app using this useGlobalState, to get & set
 * values from anywhere in the app.
 *
 * Think about it as a global useState.
 */

type GlobalState = {
  nativeCurrency: {
    price: number;
    isFetching: boolean;
  };
  setNativeCurrencyPrice: (newNativeCurrencyPriceState: number) => void;
  setIsNativeCurrencyFetching: (newIsNativeCurrencyFetching: boolean) => void;
  targetNetwork: ChainWithAttributes;
  setTargetNetwork: (newTargetNetwork: ChainWithAttributes) => void;
};

export const useGlobalState = create<GlobalState>(set => ({
  nativeCurrency: {
    price: 0,
    isFetching: true,
  },
  setNativeCurrencyPrice: (newValue: number): void =>
    set(state => ({ nativeCurrency: { ...state.nativeCurrency, price: newValue } })),
  setIsNativeCurrencyFetching: (newValue: boolean): void =>
    set(state => ({ nativeCurrency: { ...state.nativeCurrency, isFetching: newValue } })),
  targetNetwork: scaffoldConfig.targetNetworks[0],
  setTargetNetwork: (newTargetNetwork: ChainWithAttributes) => set(() => ({ targetNetwork: newTargetNetwork })),
}));

interface NetworkState {
  selectedNetwork: string;
  setSelectedNetwork: (network: string) => void;
}

export const useNetworkStore = create<NetworkState>(set => ({
  selectedNetwork: "",
  setSelectedNetwork: network => set({ selectedNetwork: network }),
}));

type AbiInputOutput = {
  name: string;
  type: string;
  internalType?: string;
  indexed?: boolean;
};

type AbiItem = {
  name?: string;
  type: "function" | "constructor" | "event" | "error"; // Added "error"
  inputs?: AbiInputOutput[];
  outputs?: AbiInputOutput[];
  stateMutability?: "view" | "nonpayable" | "payable";
};

type ExistSm = {
  checkContract: (address: string) => { abi: AbiItem[] | null; exists: boolean } | null;
};

export const useCheckExistSm = create<ExistSm>(() => ({
  checkContract: address => {
    // Define the type for the contracts object
    const contracts: { [key: string]: AbiItem[] } = {
      "0x901647B1517fD4dBF46B27759aDd59A91CBf0759": [
        {
          inputs: [{ internalType: "address", name: "_kernelRegistryAddress", type: "address" }],
          stateMutability: "nonpayable",
          type: "constructor",
        },
        {
          inputs: [{ internalType: "uint256", name: "contractId", type: "uint256" }],
          name: "ContractDoesNotExist",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "contractId", type: "uint256" }],
          name: "InvalidContractId",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "kernelRegistry", type: "address" }],
          name: "InvalidKernelRegistryAddress",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "length", type: "uint256" }],
          name: "InvalidLength",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "totalKernelIds", type: "uint256" }],
          name: "InvalidNumberOfKernelIds",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "smartContract", type: "address" }],
          name: "InvalidSmartContractAddress",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "tokenAuthorityContract", type: "address" }],
          name: "InvalidTokenAuthorityContractAddress",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "offset", type: "uint256" },
            { internalType: "uint256", name: "highestContractId", type: "uint256" },
          ],
          name: "OffsetOutOfBounds",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "smartContract", type: "address" }],
          name: "OwnableInterfaceNotImplemented",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "owner", type: "address" }],
          name: "OwnableInvalidOwner",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "account", type: "address" }],
          name: "OwnableUnauthorizedAccount",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "smartContractOwner", type: "address" }],
          name: "SmartContractOwnerNotMatch",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "caller", type: "address" }],
          name: "UnauthorizedNotContractPropertiesOwner",
          type: "error",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "contractId", type: "uint256" },
            { indexed: true, internalType: "address", name: "contractOwner", type: "address" },
          ],
          name: "ContractPropertiesCreated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "contractId", type: "uint256" },
            { indexed: false, internalType: "uint256[]", name: "prevKernelIds", type: "uint256[]" },
            { indexed: false, internalType: "uint256[]", name: "newKernelIds", type: "uint256[]" },
          ],
          name: "KernelIdsUpdated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [{ indexed: true, internalType: "address", name: "newKernelRegistryAddress", type: "address" }],
          name: "KernelRegistryAddressUpdated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "address", name: "previousOwner", type: "address" },
            { indexed: true, internalType: "address", name: "newOwner", type: "address" },
          ],
          name: "OwnershipTransferred",
          type: "event",
        },
        {
          inputs: [],
          name: "MAX_KERNELS_PER_CONTRACT",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "", type: "address" },
            { internalType: "uint256", name: "", type: "uint256" },
          ],
          name: "contractAddressToIds",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          name: "contracts",
          outputs: [
            { internalType: "uint256", name: "contractId", type: "uint256" },
            { internalType: "address", name: "smartContractAddress", type: "address" },
            { internalType: "uint64", name: "chainId", type: "uint64" },
            { internalType: "uint8", name: "tokenAuthorityProvider", type: "uint8" },
            { internalType: "string", name: "tokenAuthorityEndpoint", type: "string" },
            { internalType: "address", name: "tokenAuthorityContractAddress", type: "address" },
            { internalType: "address", name: "contractOwner", type: "address" },
            { internalType: "uint256", name: "createdAt", type: "uint256" },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_contractId", type: "uint256" }],
          name: "getContract",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "contractId", type: "uint256" },
                { internalType: "address", name: "smartContractAddress", type: "address" },
                { internalType: "uint64", name: "chainId", type: "uint64" },
                { internalType: "uint8", name: "tokenAuthorityProvider", type: "uint8" },
                { internalType: "string", name: "tokenAuthorityEndpoint", type: "string" },
                { internalType: "address", name: "tokenAuthorityContractAddress", type: "address" },
                { internalType: "address", name: "contractOwner", type: "address" },
                { internalType: "uint256[]", name: "kernelIds", type: "uint256[]" },
                { internalType: "uint256", name: "createdAt", type: "uint256" },
              ],
              internalType: "struct ContractRegistry.ContractProperties",
              name: "",
              type: "tuple",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint256", name: "_offset", type: "uint256" },
            { internalType: "uint256", name: "_length", type: "uint256" },
          ],
          name: "getContracts",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "contractId", type: "uint256" },
                { internalType: "address", name: "smartContractAddress", type: "address" },
                { internalType: "uint64", name: "chainId", type: "uint64" },
                { internalType: "uint8", name: "tokenAuthorityProvider", type: "uint8" },
                { internalType: "string", name: "tokenAuthorityEndpoint", type: "string" },
                { internalType: "address", name: "tokenAuthorityContractAddress", type: "address" },
                { internalType: "address", name: "contractOwner", type: "address" },
                { internalType: "uint256[]", name: "kernelIds", type: "uint256[]" },
                { internalType: "uint256", name: "createdAt", type: "uint256" },
              ],
              internalType: "struct ContractRegistry.ContractProperties[]",
              name: "",
              type: "tuple[]",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "_smartContractAddress", type: "address" },
            { internalType: "uint256", name: "_offset", type: "uint256" },
            { internalType: "uint256", name: "_length", type: "uint256" },
          ],
          name: "getContractsByContractAddress",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "contractId", type: "uint256" },
                { internalType: "address", name: "smartContractAddress", type: "address" },
                { internalType: "uint64", name: "chainId", type: "uint64" },
                { internalType: "uint8", name: "tokenAuthorityProvider", type: "uint8" },
                { internalType: "string", name: "tokenAuthorityEndpoint", type: "string" },
                { internalType: "address", name: "tokenAuthorityContractAddress", type: "address" },
                { internalType: "address", name: "contractOwner", type: "address" },
                { internalType: "uint256[]", name: "kernelIds", type: "uint256[]" },
                { internalType: "uint256", name: "createdAt", type: "uint256" },
              ],
              internalType: "struct ContractRegistry.ContractProperties[]",
              name: "",
              type: "tuple[]",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "_contractOwner", type: "address" },
            { internalType: "uint256", name: "_offset", type: "uint256" },
            { internalType: "uint256", name: "_length", type: "uint256" },
          ],
          name: "getContractsByOwner",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "contractId", type: "uint256" },
                { internalType: "address", name: "smartContractAddress", type: "address" },
                { internalType: "uint64", name: "chainId", type: "uint64" },
                { internalType: "uint8", name: "tokenAuthorityProvider", type: "uint8" },
                { internalType: "string", name: "tokenAuthorityEndpoint", type: "string" },
                { internalType: "address", name: "tokenAuthorityContractAddress", type: "address" },
                { internalType: "address", name: "contractOwner", type: "address" },
                { internalType: "uint256[]", name: "kernelIds", type: "uint256[]" },
                { internalType: "uint256", name: "createdAt", type: "uint256" },
              ],
              internalType: "struct ContractRegistry.ContractProperties[]",
              name: "",
              type: "tuple[]",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_contractId", type: "uint256" }],
          name: "getMetadata",
          outputs: [
            {
              components: [
                {
                  components: [
                    { internalType: "uint256", name: "kernelId", type: "uint256" },
                    { internalType: "uint8", name: "resolverType", type: "uint8" },
                    { internalType: "uint64", name: "chainId", type: "uint64" },
                    { internalType: "address", name: "kernelContractAddress", type: "address" },
                    { internalType: "string", name: "functionSignature", type: "string" },
                    { internalType: "string", name: "functionReturnType", type: "string" },
                    { internalType: "bytes", name: "schemaCid", type: "bytes" },
                    { internalType: "bytes", name: "metadataCid", type: "bytes" },
                    { internalType: "bool", name: "isActive", type: "bool" },
                    { internalType: "uint256", name: "deactivatedAfter", type: "uint256" },
                    { internalType: "uint256", name: "fee", type: "uint256" },
                    { internalType: "uint256", name: "stakedBalance", type: "uint256" },
                    { internalType: "address", name: "kernelOwner", type: "address" },
                    { internalType: "uint256", name: "createdAt", type: "uint256" },
                  ],
                  internalType: "struct KernelRegistry.Kernel[]",
                  name: "kernels",
                  type: "tuple[]",
                },
                {
                  components: [
                    { internalType: "uint256", name: "contractId", type: "uint256" },
                    { internalType: "address", name: "smartContractAddress", type: "address" },
                    { internalType: "uint64", name: "chainId", type: "uint64" },
                    { internalType: "uint8", name: "tokenAuthorityProvider", type: "uint8" },
                    { internalType: "string", name: "tokenAuthorityEndpoint", type: "string" },
                    { internalType: "address", name: "tokenAuthorityContractAddress", type: "address" },
                    { internalType: "address", name: "contractOwner", type: "address" },
                    { internalType: "uint256[]", name: "kernelIds", type: "uint256[]" },
                    { internalType: "uint256", name: "createdAt", type: "uint256" },
                  ],
                  internalType: "struct ContractRegistry.ContractProperties",
                  name: "contractProperty",
                  type: "tuple",
                },
              ],
              internalType: "struct ContractRegistry.Metadata",
              name: "",
              type: "tuple",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "contractOwner", type: "address" }],
          name: "getOwnerContractsCount",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "_smartContractAddress", type: "address" }],
          name: "getSmartContractOwnership",
          outputs: [{ internalType: "address", name: "", type: "address" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "highestContractId",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "owner",
          outputs: [{ internalType: "address", name: "", type: "address" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "", type: "address" },
            { internalType: "uint256", name: "", type: "uint256" },
          ],
          name: "ownerContracts",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint64", name: "_chainId", type: "uint64" },
            { internalType: "address", name: "_smartContractAddress", type: "address" },
            { internalType: "uint8", name: "_tokenAuthorityProvider", type: "uint8" },
            { internalType: "string", name: "_tokenAuthorityEndpoint", type: "string" },
            { internalType: "address", name: "_tokenAuthorityContractAddress", type: "address" },
            { internalType: "uint256[]", name: "_kernelIds", type: "uint256[]" },
          ],
          name: "registerSmartContract",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        { inputs: [], name: "renounceOwnership", outputs: [], stateMutability: "nonpayable", type: "function" },
        {
          inputs: [{ internalType: "address", name: "_kernelRegistryAddress", type: "address" }],
          name: "setKernelRegistryAddress",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "newOwner", type: "address" }],
          name: "transferOwnership",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint256", name: "_contractId", type: "uint256" },
            { internalType: "uint256[]", name: "_kernelIds", type: "uint256[]" },
          ],
          name: "updateKernelIds",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
      ] as AbiItem[],
      "0xB93acF8cEB94E0cDa52400dd4eA714bc2957AA9d": [
        {
          inputs: [{ internalType: "address", name: "_stakeToken", type: "address" }],
          stateMutability: "nonpayable",
          type: "constructor",
        },
        {
          inputs: [{ internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "ActiveKernelRequired",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "target", type: "address" }],
          name: "AddressEmptyCode",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "account", type: "address" }],
          name: "AddressInsufficientBalance",
          type: "error",
        },
        { inputs: [], name: "FailedInnerCall", type: "error" },
        {
          inputs: [{ internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "InactiveKernelRequired",
          type: "error",
        },
        {
          inputs: [
            { internalType: "address", name: "caller", type: "address" },
            { internalType: "uint256", name: "amount", type: "uint256" },
          ],
          name: "InsufficientBalance",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "InvalidKernelId",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "length", type: "uint256" }],
          name: "InvalidLength",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "stakeToken", type: "address" }],
          name: "InvalidStakeTokenAddress",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "amount", type: "uint256" }],
          name: "InvalidUnstakeAmount",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "KernelDoesNotExist",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "provided", type: "uint256" },
            { internalType: "uint256", name: "required", type: "uint256" },
          ],
          name: "MinimumStakeNotMet",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "offset", type: "uint256" },
            { internalType: "uint256", name: "highestKernelId", type: "uint256" },
          ],
          name: "OffsetOutOfBounds",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "owner", type: "address" }],
          name: "OwnableInvalidOwner",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "account", type: "address" }],
          name: "OwnableUnauthorizedAccount",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "PendingUnstakeExists",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "PendingUnstakeNotFound",
          type: "error",
        },
        { inputs: [], name: "ReentrancyGuardReentrantCall", type: "error" },
        {
          inputs: [{ internalType: "address", name: "token", type: "address" }],
          name: "SafeERC20FailedOperation",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "provided", type: "uint256" },
            { internalType: "uint256", name: "required", type: "uint256" },
          ],
          name: "StakeAllowanceNotMet",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "provided", type: "uint256" },
            { internalType: "uint256", name: "required", type: "uint256" },
          ],
          name: "TimeExceeded",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "caller", type: "address" }],
          name: "UnauthorizedNotKernelOwner",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "provided", type: "uint256" },
            { internalType: "uint256", name: "required", type: "uint256" },
          ],
          name: "WaitingPeriodNotOver",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "provided", type: "uint256" },
            { internalType: "uint8", name: "feeDecimals", type: "uint8" },
          ],
          name: "WholeNumberInDecimalsRequired",
          type: "error",
        },
        {
          anonymous: false,
          inputs: [{ indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "DeactivationCancelled",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [{ indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "DeactivationInitiated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" },
            { indexed: true, internalType: "address", name: "kernelOwner", type: "address" },
          ],
          name: "KernelCreated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [{ indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" }],
          name: "KernelDeactivated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [{ indexed: false, internalType: "uint256", name: "newMinimumStake", type: "uint256" }],
          name: "MinimumStakeUpdated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "address", name: "previousOwner", type: "address" },
            { indexed: true, internalType: "address", name: "newOwner", type: "address" },
          ],
          name: "OwnershipTransferred",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" },
            { indexed: false, internalType: "uint256", name: "amount", type: "uint256" },
          ],
          name: "Staked",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" },
            { indexed: false, internalType: "uint256", name: "amount", type: "uint256" },
          ],
          name: "UnstakeCancelled",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" },
            { indexed: false, internalType: "uint256", name: "amount", type: "uint256" },
          ],
          name: "UnstakeInitiated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "kernelId", type: "uint256" },
            { indexed: false, internalType: "uint256", name: "amount", type: "uint256" },
          ],
          name: "Unstaked",
          type: "event",
        },
        {
          inputs: [],
          name: "FEE_DECIMALS",
          outputs: [{ internalType: "uint8", name: "", type: "uint8" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "STAKE_DECIMALS",
          outputs: [{ internalType: "uint8", name: "", type: "uint8" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "WAITING_PERIOD",
          outputs: [{ internalType: "uint32", name: "", type: "uint32" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_kernelId", type: "uint256" }],
          name: "cancelDeactivation",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_kernelId", type: "uint256" }],
          name: "cancelUnstake",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_kernelId", type: "uint256" }],
          name: "completeDeactivation",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_kernelId", type: "uint256" }],
          name: "completeUnstake",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_kernelId", type: "uint256" }],
          name: "getKernel",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "kernelId", type: "uint256" },
                { internalType: "uint8", name: "resolverType", type: "uint8" },
                { internalType: "uint64", name: "chainId", type: "uint64" },
                { internalType: "address", name: "kernelContractAddress", type: "address" },
                { internalType: "string", name: "functionSignature", type: "string" },
                { internalType: "string", name: "functionReturnType", type: "string" },
                { internalType: "bytes", name: "schemaCid", type: "bytes" },
                { internalType: "bytes", name: "metadataCid", type: "bytes" },
                { internalType: "bool", name: "isActive", type: "bool" },
                { internalType: "uint256", name: "deactivatedAfter", type: "uint256" },
                { internalType: "uint256", name: "fee", type: "uint256" },
                { internalType: "uint256", name: "stakedBalance", type: "uint256" },
                { internalType: "address", name: "kernelOwner", type: "address" },
                { internalType: "uint256", name: "createdAt", type: "uint256" },
              ],
              internalType: "struct KernelRegistry.Kernel",
              name: "",
              type: "tuple",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint256", name: "_offset", type: "uint256" },
            { internalType: "uint256", name: "_length", type: "uint256" },
          ],
          name: "getKernels",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "kernelId", type: "uint256" },
                { internalType: "uint8", name: "resolverType", type: "uint8" },
                { internalType: "uint64", name: "chainId", type: "uint64" },
                { internalType: "address", name: "kernelContractAddress", type: "address" },
                { internalType: "string", name: "functionSignature", type: "string" },
                { internalType: "string", name: "functionReturnType", type: "string" },
                { internalType: "bytes", name: "schemaCid", type: "bytes" },
                { internalType: "bytes", name: "metadataCid", type: "bytes" },
                { internalType: "bool", name: "isActive", type: "bool" },
                { internalType: "uint256", name: "deactivatedAfter", type: "uint256" },
                { internalType: "uint256", name: "fee", type: "uint256" },
                { internalType: "uint256", name: "stakedBalance", type: "uint256" },
                { internalType: "address", name: "kernelOwner", type: "address" },
                { internalType: "uint256", name: "createdAt", type: "uint256" },
              ],
              internalType: "struct KernelRegistry.Kernel[]",
              name: "",
              type: "tuple[]",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "_kernelOwner", type: "address" },
            { internalType: "uint256", name: "_offset", type: "uint256" },
            { internalType: "uint256", name: "_length", type: "uint256" },
          ],
          name: "getKernelsByOwner",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "kernelId", type: "uint256" },
                { internalType: "uint8", name: "resolverType", type: "uint8" },
                { internalType: "uint64", name: "chainId", type: "uint64" },
                { internalType: "address", name: "kernelContractAddress", type: "address" },
                { internalType: "string", name: "functionSignature", type: "string" },
                { internalType: "string", name: "functionReturnType", type: "string" },
                { internalType: "bytes", name: "schemaCid", type: "bytes" },
                { internalType: "bytes", name: "metadataCid", type: "bytes" },
                { internalType: "bool", name: "isActive", type: "bool" },
                { internalType: "uint256", name: "deactivatedAfter", type: "uint256" },
                { internalType: "uint256", name: "fee", type: "uint256" },
                { internalType: "uint256", name: "stakedBalance", type: "uint256" },
                { internalType: "address", name: "kernelOwner", type: "address" },
                { internalType: "uint256", name: "createdAt", type: "uint256" },
              ],
              internalType: "struct KernelRegistry.Kernel[]",
              name: "",
              type: "tuple[]",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "kernelOwner", type: "address" }],
          name: "getOwnerKernelsCount",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "highestKernelId",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_kernelId", type: "uint256" }],
          name: "initiateDeactivation",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint256", name: "_kernelId", type: "uint256" },
            { internalType: "uint256", name: "_amount", type: "uint256" },
          ],
          name: "initiateUnstake",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          name: "kernels",
          outputs: [
            { internalType: "uint256", name: "kernelId", type: "uint256" },
            { internalType: "uint8", name: "resolverType", type: "uint8" },
            { internalType: "uint64", name: "chainId", type: "uint64" },
            { internalType: "address", name: "kernelContractAddress", type: "address" },
            { internalType: "string", name: "functionSignature", type: "string" },
            { internalType: "string", name: "functionReturnType", type: "string" },
            { internalType: "bytes", name: "schemaCid", type: "bytes" },
            { internalType: "bytes", name: "metadataCid", type: "bytes" },
            { internalType: "bool", name: "isActive", type: "bool" },
            { internalType: "uint256", name: "deactivatedAfter", type: "uint256" },
            { internalType: "uint256", name: "fee", type: "uint256" },
            { internalType: "uint256", name: "stakedBalance", type: "uint256" },
            { internalType: "address", name: "kernelOwner", type: "address" },
            { internalType: "uint256", name: "createdAt", type: "uint256" },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "minimumStake",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "owner",
          outputs: [{ internalType: "address", name: "", type: "address" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "", type: "address" },
            { internalType: "uint256", name: "", type: "uint256" },
          ],
          name: "ownerKernels",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint8", name: "_resolverType", type: "uint8" },
            { internalType: "uint64", name: "_chainId", type: "uint64" },
            { internalType: "address", name: "_kernelContractAddress", type: "address" },
            { internalType: "string", name: "_functionSignature", type: "string" },
            { internalType: "string", name: "_functionReturnType", type: "string" },
            { internalType: "bytes", name: "_schemaCid", type: "bytes" },
            { internalType: "bytes", name: "_metadataCid", type: "bytes" },
            { internalType: "uint256", name: "_fee", type: "uint256" },
            { internalType: "uint256", name: "_initialStake", type: "uint256" },
          ],
          name: "registerKernel",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        { inputs: [], name: "renounceOwnership", outputs: [], stateMutability: "nonpayable", type: "function" },
        {
          inputs: [{ internalType: "uint256", name: "_newMinimumStake", type: "uint256" }],
          name: "setMinimumStake",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint256", name: "_kernelId", type: "uint256" },
            { internalType: "uint256", name: "_amount", type: "uint256" },
          ],
          name: "stake",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [],
          name: "stakeToken",
          outputs: [{ internalType: "contract IERC20", name: "", type: "address" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "newOwner", type: "address" }],
          name: "transferOwnership",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          name: "unstakes",
          outputs: [
            { internalType: "uint256", name: "unstakeAmount", type: "uint256" },
            { internalType: "uint256", name: "unstakedAfter", type: "uint256" },
          ],
          stateMutability: "view",
          type: "function",
        },
      ] as AbiItem[],
      "0x6b96E52Cc40136E22eF690bA0C28E521a86AAc4D": [
        {
          inputs: [],
          stateMutability: "nonpayable",
          type: "constructor",
        },
        {
          inputs: [{ internalType: "uint256", name: "dappId", type: "uint256" }],
          name: "DappDoesNotExist",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "dappId", type: "uint256" }],
          name: "InvalidDappId",
          type: "error",
        },
        {
          inputs: [{ internalType: "uint256", name: "length", type: "uint256" }],
          name: "InvalidLength",
          type: "error",
        },
        {
          inputs: [
            { internalType: "uint256", name: "offset", type: "uint256" },
            { internalType: "uint256", name: "highestDappId", type: "uint256" },
          ],
          name: "OffsetOutOfBounds",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "owner", type: "address" }],
          name: "OwnableInvalidOwner",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "account", type: "address" }],
          name: "OwnableUnauthorizedAccount",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "caller", type: "address" }],
          name: "UnauthorizedNotDappOwner",
          type: "error",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "uint256", name: "dappId", type: "uint256" },
            { indexed: true, internalType: "address", name: "dappOwner", type: "address" },
          ],
          name: "DappCreated",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "address", name: "previousOwner", type: "address" },
            { indexed: true, internalType: "address", name: "newOwner", type: "address" },
          ],
          name: "OwnershipTransferred",
          type: "event",
        },
        {
          inputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          name: "dapps",
          outputs: [
            { internalType: "uint256", name: "dappId", type: "uint256" },
            { internalType: "uint256", name: "contractId", type: "uint256" },
            { internalType: "bytes32", name: "entryId", type: "bytes32" },
            { internalType: "address", name: "dappOwner", type: "address" },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
          name: "entries",
          outputs: [
            { internalType: "uint256", name: "contractId", type: "uint256" },
            { internalType: "address", name: "dappOwner", type: "address" },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_dappId", type: "uint256" }],
          name: "getDapp",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "dappId", type: "uint256" },
                { internalType: "uint256", name: "contractId", type: "uint256" },
                { internalType: "bytes32", name: "entryId", type: "bytes32" },
                { internalType: "address", name: "dappOwner", type: "address" },
              ],
              internalType: "struct DappRegistry.Dapp",
              name: "",
              type: "tuple",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "uint256", name: "_offset", type: "uint256" },
            { internalType: "uint256", name: "_length", type: "uint256" },
          ],
          name: "getDapps",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "dappId", type: "uint256" },
                { internalType: "uint256", name: "contractId", type: "uint256" },
                { internalType: "bytes32", name: "entryId", type: "bytes32" },
                { internalType: "address", name: "dappOwner", type: "address" },
              ],
              internalType: "struct DappRegistry.Dapp[]",
              name: "",
              type: "tuple[]",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "_dappOwner", type: "address" },
            { internalType: "uint256", name: "_offset", type: "uint256" },
            { internalType: "uint256", name: "_length", type: "uint256" },
          ],
          name: "getDappsByOwner",
          outputs: [
            {
              components: [
                { internalType: "uint256", name: "dappId", type: "uint256" },
                { internalType: "uint256", name: "contractId", type: "uint256" },
                { internalType: "bytes32", name: "entryId", type: "bytes32" },
                { internalType: "address", name: "dappOwner", type: "address" },
              ],
              internalType: "struct DappRegistry.Dapp[]",
              name: "",
              type: "tuple[]",
            },
          ],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "dappOwner", type: "address" }],
          name: "getOwnerDappsCount",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "highestDappId",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "owner",
          outputs: [{ internalType: "address", name: "", type: "address" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "", type: "address" },
            { internalType: "uint256", name: "", type: "uint256" },
          ],
          name: "ownerDapps",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "_contractId", type: "uint256" }],
          name: "registerDapp",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [],
          name: "renounceOwnership",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "newOwner", type: "address" }],
          name: "transferOwnership",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
      ] as AbiItem[],
      "0xE21d9A238ad514Ab5D01c15557B6878c3816799D": [
        {
          inputs: [
            { internalType: "string", name: "name", type: "string" },
            { internalType: "string", name: "symbol", type: "string" },
            { internalType: "address", name: "owner", type: "address" },
            { internalType: "address", name: "faucet", type: "address" },
            { internalType: "uint256", name: "initialSupply", type: "uint256" },
          ],
          stateMutability: "nonpayable",
          type: "constructor",
        },
        { inputs: [], name: "AccessControlBadConfirmation", type: "error" },
        {
          inputs: [
            { internalType: "address", name: "account", type: "address" },
            { internalType: "bytes32", name: "neededRole", type: "bytes32" },
          ],
          name: "AccessControlUnauthorizedAccount",
          type: "error",
        },
        {
          inputs: [
            { internalType: "address", name: "spender", type: "address" },
            { internalType: "uint256", name: "allowance", type: "uint256" },
            { internalType: "uint256", name: "needed", type: "uint256" },
          ],
          name: "ERC20InsufficientAllowance",
          type: "error",
        },
        {
          inputs: [
            { internalType: "address", name: "sender", type: "address" },
            { internalType: "uint256", name: "balance", type: "uint256" },
            { internalType: "uint256", name: "needed", type: "uint256" },
          ],
          name: "ERC20InsufficientBalance",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "approver", type: "address" }],
          name: "ERC20InvalidApprover",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "receiver", type: "address" }],
          name: "ERC20InvalidReceiver",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "sender", type: "address" }],
          name: "ERC20InvalidSender",
          type: "error",
        },
        {
          inputs: [{ internalType: "address", name: "spender", type: "address" }],
          name: "ERC20InvalidSpender",
          type: "error",
        },
        { inputs: [], name: "EnforcedPause", type: "error" },
        { inputs: [], name: "ExpectedPause", type: "error" },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "address", name: "owner", type: "address" },
            { indexed: true, internalType: "address", name: "spender", type: "address" },
            { indexed: false, internalType: "uint256", name: "value", type: "uint256" },
          ],
          name: "Approval",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [{ indexed: false, internalType: "address", name: "account", type: "address" }],
          name: "Paused",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "bytes32", name: "role", type: "bytes32" },
            { indexed: true, internalType: "bytes32", name: "previousAdminRole", type: "bytes32" },
            { indexed: true, internalType: "bytes32", name: "newAdminRole", type: "bytes32" },
          ],
          name: "RoleAdminChanged",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "bytes32", name: "role", type: "bytes32" },
            { indexed: true, internalType: "address", name: "account", type: "address" },
            { indexed: true, internalType: "address", name: "sender", type: "address" },
          ],
          name: "RoleGranted",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "bytes32", name: "role", type: "bytes32" },
            { indexed: true, internalType: "address", name: "account", type: "address" },
            { indexed: true, internalType: "address", name: "sender", type: "address" },
          ],
          name: "RoleRevoked",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [
            { indexed: true, internalType: "address", name: "from", type: "address" },
            { indexed: true, internalType: "address", name: "to", type: "address" },
            { indexed: false, internalType: "uint256", name: "value", type: "uint256" },
          ],
          name: "Transfer",
          type: "event",
        },
        {
          anonymous: false,
          inputs: [{ indexed: false, internalType: "address", name: "account", type: "address" }],
          name: "Unpaused",
          type: "event",
        },
        {
          inputs: [],
          name: "DEFAULT_ADMIN_ROLE",
          outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "MINTER_ROLE",
          outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "PAUSER_ROLE",
          outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "owner", type: "address" },
            { internalType: "address", name: "spender", type: "address" },
          ],
          name: "allowance",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "spender", type: "address" },
            { internalType: "uint256", name: "value", type: "uint256" },
          ],
          name: "approve",
          outputs: [{ internalType: "bool", name: "", type: "bool" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "account", type: "address" }],
          name: "balanceOf",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint256", name: "value", type: "uint256" }],
          name: "burn",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "account", type: "address" },
            { internalType: "uint256", name: "value", type: "uint256" },
          ],
          name: "burnFrom",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [],
          name: "decimals",
          outputs: [{ internalType: "uint8", name: "", type: "uint8" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [{ internalType: "bytes32", name: "role", type: "bytes32" }],
          name: "getRoleAdmin",
          outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "bytes32", name: "role", type: "bytes32" },
            { internalType: "address", name: "account", type: "address" },
          ],
          name: "grantRole",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "bytes32", name: "role", type: "bytes32" },
            { internalType: "address", name: "account", type: "address" },
          ],
          name: "hasRole",
          outputs: [{ internalType: "bool", name: "", type: "bool" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "to", type: "address" },
            { internalType: "uint256", name: "amount", type: "uint256" },
          ],
          name: "mint",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [],
          name: "name",
          outputs: [{ internalType: "string", name: "", type: "string" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "paused",
          outputs: [{ internalType: "bool", name: "", type: "bool" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "bytes32", name: "role", type: "bytes32" },
            { internalType: "address", name: "callerConfirmation", type: "address" },
          ],
          name: "renounceRole",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "bytes32", name: "role", type: "bytes32" },
            { internalType: "address", name: "account", type: "address" },
          ],
          name: "revokeRole",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "bytes4", name: "interfaceId", type: "bytes4" }],
          name: "supportsInterface",
          outputs: [{ internalType: "bool", name: "", type: "bool" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "symbol",
          outputs: [{ internalType: "string", name: "", type: "string" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [],
          name: "totalSupply",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "to", type: "address" },
            { internalType: "uint256", name: "value", type: "uint256" },
          ],
          name: "transfer",
          outputs: [{ internalType: "bool", name: "", type: "bool" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "from", type: "address" },
            { internalType: "address", name: "to", type: "address" },
            { internalType: "uint256", name: "value", type: "uint256" },
          ],
          name: "transferFrom",
          outputs: [{ internalType: "bool", name: "", type: "bool" }],
          stateMutability: "nonpayable",
          type: "function",
        },
      ] as AbiItem[],
    };

    const abi = contracts[address] || null;
    const exists = !!abi;

    return { abi, exists };
  },
}));
