"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { useCheckExistSm } from "../services/store/store";
import { ethers } from "ethers";
import type { NextPage } from "next";
import { useAccount } from "wagmi";
import { motion } from "framer-motion";
import { NetworkDropdown } from "~~/components/DropDown";
import { Address } from "~~/components/scaffold-eth";
import { addContractToDeployedContracts } from "~~/contracts/deployedContracts";
import { useTargetNetwork } from "~~/hooks/scaffold-eth";

const Home: NextPage = () => {
  const { address: connectedAddress } = useAccount();
  const [contractAddress, setContractAddress] = useState<string>("");
  const [contractAbi, setContractAbi] = useState<object[]>([]);
  const [selectedAbiFileName, setSelectedAbiFileName] = useState<string>("Select ABI File");
  const [contractExists, setContractExists] = useState<boolean | null>(null);
  const [selectedNetwork, setSelectedNetwork] = useState<number>(0);
  const [contractAbiText, setContractAbiText] = useState<string>("");

  const router = useRouter();
  const checkContract = useCheckExistSm(state => state.checkContract);
  const { targetNetwork } = useTargetNetwork();

  const handleSubmit = () => {
    if (!selectedNetwork || !contractAddress || contractAbi.length === 0) {
      console.error("Please select a network, input a contract address, and select an ABI file.");
      return;
    }

    addContractToDeployedContracts(selectedNetwork, "UserContract", contractAddress, contractAbi);
    console.log("User Contract added to deployedContracts.");
    router.push("/debug");
  };

  const handleContractAddressChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setContractAddress(event.target.value);
  };

  const handleCheckExist = () => {
    setContractAbiText("");
    const contractResult = checkContract(contractAddress);
    if (contractResult?.exists) {
      const contractResult = checkContract(contractAddress);
      if (contractResult?.exists && contractResult.abi) {
        const abiString = JSON.stringify(contractResult.abi, null, 2);
        setContractAbiText(abiString);
        setContractAbi(contractResult.abi);
      }
      setContractExists(true);
    } else {
      setContractExists(false);
    }
  };

  const handleAbiFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = e => {
        try {
          const parsedAbi = JSON.parse(e.target?.result as string);
          if (!Array.isArray(parsedAbi)) {
            throw new Error("Invalid ABI format. Expected an array.");
          }
          setContractAbi(parsedAbi);
          setSelectedAbiFileName(file.name);
        } catch (error) {
          console.error("Invalid ABI file", error);
          alert("The selected file is not a valid ABI JSON file. Please upload a valid file.");
          setContractAbi([]);
          setSelectedAbiFileName("Select ABI File");
        }
      };
      reader.onerror = () => {
        console.error("Error reading the file.");
        alert("Failed to read the selected file. Please try again.");
        setContractAbi([]);
        setSelectedAbiFileName("Select ABI File");
      };
      reader.readAsText(file);
    }
  };

  const handleAbiTextChange = (text: string) => {
    setContractAbiText(text);
    try {
      const parsedAbi = JSON.parse(text);
      setContractAbi(parsedAbi);
    } catch (error) {
      console.error("Invalid ABI JSON format", error);
    }
  };

  const handleCheckContract = async () => {
    if (!contractAddress) {
      setContractExists(null);
      return;
    }
    try {
      console.log("Checking target network:", targetNetwork);
      const rpcUrl = targetNetwork.rpcUrls.default?.http?.[0];

      if (typeof rpcUrl !== "string" || !rpcUrl) {
        console.error("Invalid RPC URL format:", rpcUrl);
        setContractExists(false);
        return;
      }
      const provider = new ethers.JsonRpcProvider(rpcUrl);
      const code = await provider.getCode(contractAddress);
      const isContract = code !== "0x";

      setContractExists(isContract);
      setContractAddress(contractAddress);

      if (targetNetwork.rpcUrls.default?.http?.[0] == "https://rpc2.sepolia.org") {
        const blockNumber = await provider.getBlockNumber();
        const allLogs = await provider.getLogs({
          address: contractAddress,
          fromBlock: blockNumber - 1000,
          toBlock: blockNumber,
        });
        console.log(`Logs from the contract:${blockNumber - 1000} to ${blockNumber}`, allLogs);
      } else {
        const blockNumber = await provider.getBlockNumber();
        const allLogs = await provider.getLogs({
          address: contractAddress,
          fromBlock: blockNumber - blockNumber,
          toBlock: blockNumber,
        });
        console.log(`Logs from the contract:${blockNumber - blockNumber} to ${blockNumber}`, allLogs);

        const txHash = allLogs[0]?.transactionHash;
        if (txHash) {
          await logTransactionByHash(provider, txHash);
        } else {
          console.warn("No logs found or no transaction hash available.");
        }
      }
    } catch (error) {
      console.error("Error checking contract:", error);
      setContractExists(false);
    }
  };

  const logTransactionByHash = async (provider: ethers.JsonRpcProvider, txHash: string) => {
    try {
      const transaction = await provider.getTransaction(txHash);
      console.log(`Transaction details for hash ${txHash}:`, transaction);
    } catch (error) {
      console.error(`Error fetching transaction with hash ${txHash}:`, error);
    }
  };

  const handleSelectAbiClick = () => {
    document.getElementById("abiFileInput")?.click();
  };

  return (
    <div className="flex items-center flex-col flex-grow pt-10">
      <motion.div
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, ease: "easeOut" }}
        className="px-5"
      >
        <div className="flex justify-center items-center space-x-2 flex-col sm:flex-row">
          <p className="my-2 font-medium">Connected Address:</p>
          <Address address={connectedAddress} />
        </div>
        <div className="flex gap-x-3 items-center justify-center text-center">
          <p className="font-medium">Check if your Smart Contracts Exist :</p>
          {contractExists === null ? (
            ""
          ) : contractExists ? (
            <>
              <span className="text-green-500">Contract Exists ✅</span>
              {checkContract(contractAddress) ? (
                <span className="text-green-500 ml-2">ABI Exists ✅</span>
              ) : (
                <span className="text-red-500 ml-2">ABI Not Found ❌</span>
              )}
            </>
          ) : (
            <span className="text-red-500">Contract Not Found ❌</span>
          )}
        </div>

        {/* Dropdown and Input with ABI Button */}
        <div className="flex justify-center items-center space-x-4 mt-4">
          <div className="flex items-center space-x-0">
            <NetworkDropdown onChange={value => setSelectedNetwork(Number(value))} />
            <input
              type="text"
              className="input bg-zinc-800 w-64 rounded-md border border-little"
              placeholder="Enter Contract Address"
              value={contractAddress}
              onChange={handleContractAddressChange}
            />
          </div>
          <button
            onClick={handleSelectAbiClick}
            className="px-4 py-2 text-white bg-little rounded-lg border border-white hover:bg-zinc-500"
            disabled={contractExists === true}
          >
            {selectedAbiFileName}
          </button>
          <input type="file" id="abiFileInput" className="hidden" accept=".json" onChange={handleAbiFileChange} />
        </div>
        <div className="flex flex-col w-full text-center mt-3">
          <div className="flex justify-center items-center space-x-2">
            <button
              className="px-3 py-1 text-black bg-green-500 rounded-md hover:bg-green-700 text-sm"
              onClick={handleCheckContract}
            >
              Check Contract Exist
            </button>
            <button
              className="px-3 py-1 text-black bg-green-500 rounded-md hover:bg-green-700 text-sm"
              onClick={handleCheckExist}
            >
              Check ABI
            </button>
          </div>
          <h1 className="text-xl font-semibold"></h1>
          <p className="mt-0">Paste Your ABI Here.</p>

          <textarea
            className="bg-zinc-800 w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-zinc-500"
            placeholder="Paste your ABI JSON here"
            rows={6}
            value={contractAbiText}
            onChange={e => handleAbiTextChange(e.target.value)}
          />
        </div>
        {/* Submit Button */}
        <div className="flex w-full justify-center py-4 rounded-full">
          <button onClick={handleSubmit} className="px-4 py-2 text-black bg-green-500 rounded-lg hover:bg-green-700">
            Submit
          </button>
        </div>
      </motion.div>
    </div>
  );
};

export default Home;
