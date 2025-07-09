import { GenericContractsDeclaration } from "~~/utils/scaffold-eth/contract";

const deployedContracts: GenericContractsDeclaration = {
  11155111: {},
};

export function addContractToDeployedContracts(
  network: number,
  contractName: string,
  contractAddress: string,
  contractAbi: any,
) {
  if (!deployedContracts[network]) {
    deployedContracts[network] = {};
  }
  deployedContracts[network][contractName] = {
    address: contractAddress,
    abi: contractAbi,
    inheritedFunctions: {},
  };

  console.log(`Added/Updated contract "${contractName}" on network ${network}`);
  return deployedContracts;
}

export default deployedContracts satisfies GenericContractsDeclaration;
