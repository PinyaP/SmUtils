import { getBlockExplorerTxLink } from "./scaffold-eth";
import { notification } from "./scaffold-eth/notification";
import { ethers } from "ethers";

const TxnNotification = ({ message, blockExplorerLink }: { message: string; blockExplorerLink?: string }) => {
  return (
    <div className={`flex flex-col ml-1 cursor-default`}>
      <p className="my-0">{message}</p>
      {blockExplorerLink && blockExplorerLink.length > 0 ? (
        <a href={blockExplorerLink} target="_blank" rel="noreferrer" className="block link text-md">
          check out transaction
        </a>
      ) : null}
    </div>
  );
};

export const deployContract = async (bytecode: string, abi: any, args: any[]) => {
  const network = 11155111;
  let notificationId = null;
  // eslint-disable-next-line prefer-const
  let transactionHash: string | undefined = undefined;
  let blockExplorerTxURL = "";
  const provider = new ethers.BrowserProvider(window.ethereum);
  const signer = await provider.getSigner();

  const factory = new ethers.ContractFactory(abi, bytecode, signer);
  notificationId = notification.loading(<TxnNotification message="Awaiting for user confirmation" />);
  const contract = await factory.deploy(...args);
  transactionHash = await provider.getTransaction.toString();
  notification.remove(notificationId);
  notificationId = notification.loading(
    <TxnNotification message="Waiting for transaction to complete." blockExplorerLink={blockExplorerTxURL} />,
  );
  blockExplorerTxURL = network ? getBlockExplorerTxLink(network, transactionHash) : "";
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, prefer-const
  notification.remove(notificationId);
  notification.success(
    <TxnNotification message="Transaction completed successfully!" blockExplorerLink={blockExplorerTxURL} />,
    {
      icon: "🎉",
    },
  );
  const deploymentTransaction = contract.deploymentTransaction();
  if (!deploymentTransaction) {
    throw new Error("Failed to get deployment transaction. Ensure the contract is deployed correctly.");
  }

  const receipt = await deploymentTransaction.wait();
  console.log(receipt);

  console.log("Contract deployed at:", contract.target);
  return contract;
};

export const deployContractToSapphire = async (bytecode: string, abi: any, address: any) => {
  const network = 23295;
  let notificationId = null;
  // eslint-disable-next-line prefer-const
  let transactionHash: string | undefined = undefined;
  let blockExplorerTxURL = "";

  const provider = new ethers.BrowserProvider(window.ethereum);
  const signer = await provider.getSigner();

  const factory = new ethers.ContractFactory(abi, bytecode, signer);
  notificationId = notification.loading(<TxnNotification message="Awaiting for user confirmation" />);
  const contract = await factory.deploy(address);
  transactionHash = await provider.getTransaction.toString();
  notification.remove(notificationId);
  notificationId = notification.loading(
    <TxnNotification message="Waiting for transaction to complete." blockExplorerLink={blockExplorerTxURL} />,
  );
  blockExplorerTxURL = network ? getBlockExplorerTxLink(network, transactionHash) : "";
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, prefer-const
  notification.remove(notificationId);
  notification.success(
    <TxnNotification message="Transaction completed successfully!" blockExplorerLink={blockExplorerTxURL} />,
    {
      icon: "🎉",
    },
  );

  console.log("Token Authority deployed at:", contract.getAddress());
  return contract;
};
