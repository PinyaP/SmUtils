# SmUtils – Contract Explorer & Deploy Contract

## Overview

This project is a modern dApp toolkit built on top of [Scaffold-ETH 2](https://github.com/scaffold-eth/scaffold-eth-2), providing two main features for Ethereum smart contract developers and users:

1. **Contract Explorer** – Interact with any deployed contract on Sepolia by pasting its address and ABI, even if it is not verified.
2. **Deploy Contract** – Compile and deploy your own smart contracts directly to the Sepolia Testnet, with a simple UI workflow.

Built with Next.js, Wagmi, Viem, Framer Motion, and Typescript.

---

## ✨ Features

### 1. Contract Explorer

- **Purpose:**  
  Allows users to interact with any smart contract deployed on Sepolia, even if the contract is not verified on Etherscan.
- **How it works:**  
  - Paste the contract address and ABI into the explorer.
  - The app will bring you to a debug page where you can interact with all the contract's functions and view its state.
- **Use case:**  
  Useful for developers and users who want to test, debug, or interact with contracts that are not verified or are under development.

### 2. Deploy Contract

- **Purpose:**  
  Enables users to compile and deploy Solidity smart contracts directly from the web interface.
- **How it works:**  
  - Paste or write your Solidity contract in the editor.
  - Click **Compile** to check for errors and prepare the contract.
  - Once compilation is successful, the **Deploy** button becomes active.
  - Deploy your contract to the Sepolia Testnet.
- **Note:**  
  - Currently, deployment is supported only on the Sepolia Testnet.
  - You must compile before you can deploy.

---

## 🚀 Quickstart

### Prerequisites

- [Node.js (>= v18.18)](https://nodejs.org/en/download/)
- [Yarn](https://classic.yarnpkg.com/en/docs/install/)
- [Git](https://git-scm.com/downloads)

### Setup

1. **Clone the repository and install dependencies:**
   ```bash
   git clone https://github.com/your-username/your-repo.git
   cd your-repo
   yarn install
   ```

2. **Start the local development server:**
   ```bash
   yarn start
   ```
   Visit [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧩 Project Structure

- `packages/nextjs/app/page.tsx` – Main landing page, includes Contract Explorer.
- `packages/nextjs/app/deploy/page.tsx` – Deploy Contract feature with Solidity editor, compile, and deploy workflow.
- `packages/nextjs/utils/compileSolidity.tsx` – Solidity compilation logic and dependency management.

---

## 📝 Usage

### Contract Explorer

1. Go to the home page.
2. Select the network (Sepolia).
3. Enter the contract address and paste the ABI, or upload an ABI file.
4. Click **Check Contract Exist** and **Check ABI**.
5. If the contract exists, click **Submit** to go to the debug page and interact with the contract.

### Deploy Contract

1. Go to the **Deploy Contract** page.
2. Paste or write your Solidity contract in the editor.
3. Click **Compile**.
4. Once compilation is successful (green check appears), click **Deploy**.
5. Follow MetaMask prompts to deploy to Sepolia.

---

## 📚 Documentation

- For more details on Scaffold-ETH 2, visit the [official docs](https://docs.scaffoldeth.io).
- For Next.js routing and configuration, see the [Next.js documentation](https://nextjs.org/docs).

---
**Enjoy building and exploring Ethereum smart contracts!**
