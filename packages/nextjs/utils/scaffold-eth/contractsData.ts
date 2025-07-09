import deployedContracts from "~~/contracts/deployedContracts";
import { useTargetNetwork } from "~~/hooks/scaffold-eth";
import { GenericContractsDeclaration, contracts as staticContracts } from "~~/utils/scaffold-eth/contract";

const DEFAULT_ALL_CONTRACTS: GenericContractsDeclaration = {};

export function useAllContracts() {
  const { targetNetwork } = useTargetNetwork();

  // Use updated deployedContracts that now includes user-added contracts
  const mergedContracts = {
    ...(deployedContracts?.[targetNetwork.id as keyof typeof deployedContracts] || {}),
    ...(staticContracts?.[targetNetwork.id as keyof typeof staticContracts] || {}),
  };

  return mergedContracts || DEFAULT_ALL_CONTRACTS;
}
