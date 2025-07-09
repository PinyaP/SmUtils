"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { compileContract } from "../../utils/compileSolidity";
import { deployContract } from "../../utils/deployContract";
import { verifyContract } from "../../verify-contract";
import { TemplateDropDown } from "./_component/TemplateDropDown";
import { Editor } from "@monaco-editor/react";
import { ethers } from "krnl-sdk";
import { useAccount, useSwitchChain } from "wagmi";
// import { useWriteContract } from "wagmi";
// import { useConfig } from "wagmi";
// import { useTransactor } from "~~/hooks/scaffold-eth";

const CompileAndDeploy = () => {
  const [solidityCode, setSolidityCode] = useState<string>("");
  const [constructorArgs, setConstructorArgs] = useState<{ name: string; type: string }[]>([]);
  const [inputValues, setInputValues] = useState<Record<string, string>>({});
  const [deployedAddress, setDeployedAddress] = useState<string | null>(null);
  const [contractName, setContractName] = useState<string>("");
  const [compileSuccess, setCompileSuccess] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);

  const { chain } = useAccount();
  const { switchChain } = useSwitchChain();
  const abiCoder = new ethers.AbiCoder();

  const handleCompile = async () => {
    setIsProcessing(true);
    setCompileSuccess(false);
    try {
      const { abi, contractName: compiledName } = await compileContract(solidityCode);
      console.log("Contract Name:", compiledName);
      const constructor = abi.find((item: any) => item.type === "constructor");
      setConstructorArgs(constructor?.inputs || []);
      setContractName(compiledName);
      setCompileSuccess(true);
    } catch (err: any) {
      const errorMessage = err?.err?.message || "An unexpected error occurred.";
      console.error(errorMessage);
      setCompileSuccess(false);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDeploy = async () => {
    setIsProcessing(true);
    try {
      const expectedChainId = 11155111;
      if (chain?.id !== expectedChainId) {
        if (switchChain) {
          await switchChain({ chainId: 11155111 });
        } else {
          throw new Error(`Please switch to the correct network (chain ID: ${expectedChainId}) in MetaMask.`);
        }
      }
      const { bytecode, abi, dependencies } = await compileContract(solidityCode);
      const args = constructorArgs.map(arg => inputValues[arg.name]);
      const deployed = await deployContract(bytecode, abi, args);
      setDeployedAddress(deployed.target.toString());
      const deploymentTx = deployed.deploymentTransaction();
      if (deploymentTx) {
        await deploymentTx.wait();
      } else {
        console.warn("No deployment transaction available for this contract.");
      }
      await new Promise(resolve => setTimeout(resolve, 20000));
      const abiEncodedConstructorArgs = abiCoder.encode(
        constructorArgs.map(arg => arg.type),
        args,
      );

      const sourceCode = {
        language: "Solidity",
        sources: {
          "contract.sol": { content: solidityCode },
          ...dependencies,
        },
      };

      const apiKey = "KX34K1CZAU6NRGKDD2D9CEXC8GYWPRTCS2";
      const compilerVersion = "v0.8.24+commit.e11b9ed9";
      const optimizationUsed = "0";
      const contractAddress = deployed.target;
      await verifyContract({
        apiKey,
        chainId: expectedChainId,
        sourceCode,
        constructorArguments: abiEncodedConstructorArgs.slice(2),
        contractName: `contract.sol:${contractName}`,
        compilerVersion,
        contractAddress,
        optimizationUsed,
      });
    } catch (err) {
      console.error("Deployment error", err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleInputChange = (name: string, value: string) => {
    setInputValues(prev => ({ ...prev, [name]: value }));
  };

  const handleEditorChange = (value: string | undefined, type: "solidity" | "ta") => {
    if (type === "solidity") {
      setSolidityCode(value || "");
      setCompileSuccess(false);
    }
  };

  const handleTemplateChange = (template: { ta: string; final: string }) => {
    setSolidityCode(template.final);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-8">
      <motion.div
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, ease: "easeOut" }}
        className="w-full max-w-4xl"
      >
        <div className="flex justify-center mb-6">
          <TemplateDropDown onChange={handleTemplateChange} />
        </div>
        <div className="flex flex-col items-center">
          <div className="w-full max-w-3xl">
            <h1 className="text-xl font-semibold text-white mb-4 text-center">Deploy Your Smart Contract</h1>
            <Editor
              height="300px"
              defaultLanguage="solidity"
              value={solidityCode}
              theme="vs-dark"
              options={{
                readOnly: false,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                lineNumbers: "on",
                wordWrap: "on",
              }}
              onChange={(value: string | undefined) => handleEditorChange(value, "solidity")}
            />
            <div className="flex flex-row justify-center mt-4 gap-4 items-center">
              <button onClick={handleCompile} disabled={isProcessing} className="btn btn-primary">
                {isProcessing ? "Processing..." : "Compile"}
              </button>
              {compileSuccess && (
                <span className="ml-2 text-green-500 flex items-center" title="Compile Success">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="12" cy="12" r="12" fill="#22c55e" />
                    <path
                      d="M7 13l3 3 7-7"
                      stroke="#fff"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </span>
              )}
              <button onClick={handleDeploy} disabled={isProcessing} className="btn btn-primary">
                {isProcessing ? "Deploying..." : "Deploy"}
              </button>
            </div>
            <div className="mt-4">
              {constructorArgs.length > 0 && (
                <>
                  <h3 className="text-center mb-4">Constructor Arguments</h3>
                  {constructorArgs.map(arg => (
                    <div key={arg.name} className="mb-2">
                      <label className="block text-center">{`${arg.name} (${arg.type})`}</label>
                      <input
                        type="text"
                        value={inputValues[arg.name] || ""}
                        onChange={e => handleInputChange(arg.name, e.target.value)}
                        className="block w-full rounded-lg bg-zinc-800 border border-zinc-800 text-white p-3"
                      />
                    </div>
                  ))}
                </>
              )}
              <div className="flex flex-col items-center gap-4">
                {deployedAddress && (
                  <p className="text-center">
                    <strong className="text-green-500">Deployed Address:</strong> {deployedAddress}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default CompileAndDeploy;
