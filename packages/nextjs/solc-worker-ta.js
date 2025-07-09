self.onmessage = async event => {
  try {
    const { code, dependencySources = {} } = event.data;

    // Extract Solidity version with fallback
    const pragmaMatch = code.match(/pragma solidity \^?(\d+\.\d+\.\d+)/);
    const version = pragmaMatch ? pragmaMatch[1] : "0.8.20";

    // Fetch the Solidity compiler
    let versionList;
    try {
      const response = await fetch("https://binaries.soliditylang.org/wasm/list.json");
      versionList = await response.json();
    } catch (error) {
      throw new Error("Failed to fetch Solidity compiler version list.");
    }

    const solcFilename = versionList.releases[version];
    if (!solcFilename) throw new Error(`Requested Solidity version ${version} is not supported.`);

    const solcUrl = `https://binaries.soliditylang.org/wasm/${solcFilename}`;
    importScripts(solcUrl);

    const solc = self.Module; // WASM Module
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const solcWrapper = require("solc/wrapper");
    const solcInstance = solcWrapper(solc);

    const input = {
      language: "Solidity",
      sources: {
        "contract.sol": { content: code },
        ...dependencySources,
      },
      settings: {
        viaIR: true,
        optimizer: {
          enabled: true,
          runs: 200,
        },
        outputSelection: {
          "*": {
            "*": ["abi", "evm.bytecode"],
          },
        },
      },
    };

    console.log("Compiling with Solidity version:", version);
    const output = JSON.parse(solcInstance.compile(JSON.stringify(input)));
    console.log("Output", output);

    if (output.errors) {
      const errors = output.errors.filter(e => e.severity === "error");
      if (errors.length) throw new Error(errors.map(e => e.formattedMessage).join("\n"));
    }

    self.postMessage({ output });
  } catch (err) {
    console.error("Worker Error:", err.message);
    self.postMessage({ error: err.message });
  }
};
