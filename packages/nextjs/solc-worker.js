self.onmessage = async event => {
  try {
    const { code, dependencySources = {} } = event.data;
    console.log("Dependencies received by worker:", Object.keys(dependencySources));

    // Extract Solidity version
    const pragmaMatch = code.match(/pragma solidity \^?(\d+\.\d+\.\d+)/);
    if (!pragmaMatch) {
      throw new Error("Unable to detect Solidity version in the provided code.");
    }
    const version = pragmaMatch[1];

    // Fetch the correct Solidity compiler
    const response = await fetch("https://binaries.soliditylang.org/wasm/list.json");
    const versionList = await response.json();
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
        outputSelection: {
          "*": {
            "*": ["abi", "evm.bytecode"],
          },
        },
      },
    };

    const output = JSON.parse(solcInstance.compile(JSON.stringify(input)));
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
