import { useState } from "react";
import { ChevronDownIcon } from "@heroicons/react/24/solid";

type Network = {
  name: string;
  chainId: number;
  rpcUrl: string;
};

export const NetworkDropdown = ({ onChange }: { onChange: (value: number) => void }) => {
  const [selectedNetwork, setSelectedNetwork] = useState<number | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const networks = [{ name: "Sepolia Testnet", chainId: 11155111, rpcUrl: "https://rpc2.sepolia.org" }];

  const selectedNetworkName = networks.find(net => net.chainId === selectedNetwork)?.name || "Select Network";

  const switchToNetwork = async (network: Network) => {
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: `0x${network.chainId.toString(16)}` }], // Chain ID must be in hex
      });
      console.log(`Switched to ${network.name}`);
    } catch (error: any) {
      // If the network isn't added to MetaMask, add it
      if (error.code === 4902) {
        try {
          await window.ethereum.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: `0x${network.chainId.toString(16)}`,
                chainName: network.name,
                rpcUrls: [network.rpcUrl],
              },
            ],
          });
          console.log(`${network.name} added to MetaMask`);
        } catch (addError) {
          console.error(`Failed to add ${network.name}`, addError);
        }
      } else {
        console.error(`Failed to switch to ${network.name}`, error);
      }
    }
  };

  const handleSelectNetwork = (network: Network) => {
    setSelectedNetwork(network.chainId);
    onChange(network.chainId);
    switchToNetwork(network);
    setIsOpen(false);
  };

  return (
    <div className="relative">
      <button
        className="bg-zinc-700 text-white border border-white px-4 w-38 rounded-lg rounded-r-none h-12 flex items-center justify-between"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center space-x-3">
          {selectedNetworkName}
          <ChevronDownIcon className="w-3 h-3 ml-1" />
        </div>
      </button>

      {/* Dropdown menu */}
      {isOpen && (
        <ul className="absolute mt-2 bg-zinc-700 rounded-md">
          {networks.map(network => (
            <li
              key={network.chainId}
              className="cursor-pointer px-4 py-2 rounded-lg hover:bg-zinc-500 border-white"
              onClick={() => handleSelectNetwork(network)}
            >
              {network.name}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
