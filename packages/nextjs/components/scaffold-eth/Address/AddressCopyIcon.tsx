import { useState } from "react";
import CopyToClipboard from "react-copy-to-clipboard";
import { CheckCircleIcon } from "@heroicons/react/24/outline";
import { Square2StackIcon } from "@heroicons/react/24/solid";

export const AddressCopyIcon = ({ className, address }: { className?: string; address: string }) => {
  const [addressCopied, setAddressCopied] = useState(false);
  return (
    <CopyToClipboard
      text={address}
      onCopy={() => {
        setAddressCopied(true);
        setTimeout(() => {
          setAddressCopied(false);
        }, 800);
      }}
    >
      <button onClick={e => e.stopPropagation()}>
        {addressCopied ? (
          <CheckCircleIcon className={className} aria-hidden="true" />
        ) : (
          <Square2StackIcon className={className} aria-hidden="true" />
        )}
      </button>
    </CopyToClipboard>
  );
};
