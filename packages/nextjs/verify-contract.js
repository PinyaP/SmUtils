import axios from "axios";

export const verifyContract = async ({
  apiKey,
  chainId,
  sourceCode,
  constructorArguments,
  contractName,
  compilerVersion,
  contractAddress,
  optimizationUsed,
}) => {
  try {
    const url = "https://api.etherscan.io/api"; // Adjust if using Sepolia or another testnet

    const formData = new FormData();
    formData.append("module", "contract");
    formData.append("action", "verifysourcecode");
    formData.append("apikey", apiKey);
    formData.append("chainid", chainId.toString());
    formData.append("sourceCode", JSON.stringify(sourceCode));
    formData.append("constructorArguments", constructorArguments);
    formData.append("contractname", contractName);
    formData.append("compilerversion", compilerVersion);
    formData.append("contractaddress", contractAddress);
    formData.append("codeformat", "solidity-standard-json-input");
    formData.append("optimizationused", optimizationUsed);

    const response = await axios.post(url, formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    if (response.data.status === "1") {
      console.log("Verification successful:", response.data.result);
    } else {
      console.error("Verification failed:", response.data.result);
    }
  } catch (error) {
    console.error("Error during contract verification:", error.message);
  }
};
