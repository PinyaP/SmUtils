export const dependencySources: Record<string, { content: string }> = {
  "@openzeppelin/contracts/token/ERC20/IERC20.sol": {
    content: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    interface IERC20 {
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address recipient, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
    }`,
  },
  "@openzeppelin/contracts/utils/Address.sol": {
    content: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    library Address {
        function isContract(address account) internal view returns (bool) {
            return account.code.length > 0;
        }

        function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
            (bool success, bytes memory returndata) = target.call(data);
            if (!success) {
                revert(errorMessage);
            }
            return returndata;
        }
    }`,
  },
  "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol": {
    content: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    import "../IERC20.sol";
    import "../../../utils/Address.sol";

    library SafeERC20 {
        using Address for address;

        function safeTransfer(IERC20 token, address to, uint256 value) internal {
            _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
        }

        function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
            _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
        }

        function _callOptionalReturn(IERC20 token, bytes memory data) private {
            bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
            if (returndata.length > 0) {
                require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
            }
        }
    }`,
  },
  "@openzeppelin/contracts/access/Ownable.sol": {
    content: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    abstract contract Ownable {
        address private _owner;

        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

        constructor(address initialOwner) {
            _transferOwnership(initialOwner);
        }

        function owner() public view virtual returns (address) {
            return _owner;
        }

        modifier onlyOwner() {
            require(owner() == msg.sender, "Ownable: caller is not the owner");
            _;
        }

        function transferOwnership(address newOwner) public virtual onlyOwner {
            require(newOwner != address(0), "Ownable: new owner is the zero address");
            _transferOwnership(newOwner);
        }

        function _transferOwnership(address newOwner) internal virtual {
            address oldOwner = _owner;
            _owner = newOwner;
            emit OwnershipTransferred(oldOwner, newOwner);
        }
    }`,
  },
  "openzeppelin-solidity/contracts/utils/math/SafeMath.sol": {
    content: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    library SafeMath {
        function add(uint256 a, uint256 b) internal pure returns (uint256) {
            uint256 c = a + b;
            require(c >= a, "SafeMath: addition overflow");
            return c;
        }
    }`,
  },
  "@openzeppelin/contracts/utils/ReentrancyGuard.sol": {
    content: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    abstract contract ReentrancyGuard {
        uint256 private constant _NOT_ENTERED = 1;
        uint256 private constant _ENTERED = 2;

        uint256 private _status;

        constructor() {
            _status = _NOT_ENTERED;
        }

        modifier nonReentrant() {
            require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
            _status = _ENTERED;
            _;
            _status = _NOT_ENTERED;
        }
    }`,
  },
  "@openzeppelin/contracts/utils/cryptography/ECDSA.sol": {
    content: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    library ECDSA {
        function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
            if (signature.length != 65) {
                revert("ECDSA: invalid signature length");
            }
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            if (v < 27) {
                v += 27;
            }
            if (v != 27 && v != 28) {
                revert("ECDSA: invalid signature 'v' value");
            }
            return ecrecover(hash, v, r, s);
        }
    }`,
  },
  "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol": {
    content: `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.0;

  library MessageHashUtils {
      function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
          return keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", hash));
      }

      function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
          return keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n", _toString(s.length), s));
      }

      function _toString(uint256 value) private pure returns (string memory) {
          if (value == 0) {
              return "0";
          }
          uint256 temp = value;
          uint256 digits;
          while (temp != 0) {
              digits++;
              temp /= 10;
          }
          bytes memory buffer = new bytes(digits);
          while (value != 0) {
              digits -= 1;
              buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
              value /= 10;
          }
          return string(buffer);
      }
  }`,
  },
  "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol": {
    content: `// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

library Sapphire {
    // Oasis-specific, confidential precompiles
    address internal constant RANDOM_BYTES =
        0x0100000000000000000000000000000000000001;
    address internal constant DERIVE_KEY =
        0x0100000000000000000000000000000000000002;
    address internal constant ENCRYPT =
        0x0100000000000000000000000000000000000003;
    address internal constant DECRYPT =
        0x0100000000000000000000000000000000000004;
    address internal constant GENERATE_SIGNING_KEYPAIR =
        0x0100000000000000000000000000000000000005;
    address internal constant SIGN_DIGEST =
        0x0100000000000000000000000000000000000006;
    address internal constant VERIFY_DIGEST =
        0x0100000000000000000000000000000000000007;
    address internal constant CURVE25519_PUBLIC_KEY =
        0x0100000000000000000000000000000000000008;
    address internal constant GAS_USED =
        0x0100000000000000000000000000000000000009;
    address internal constant PAD_GAS =
        0x010000000000000000000000000000000000000a;

    // Oasis-specific, general precompiles
    address internal constant SHA512_256 =
        0x0100000000000000000000000000000000000101;
    address internal constant SHA512 =
        0x0100000000000000000000000000000000000102;
    address internal constant SHA384 =
        0x0100000000000000000000000000000000000104;

    type Curve25519PublicKey is bytes32;
    type Curve25519SecretKey is bytes32;

    enum SigningAlg {
        /// Ed25519 signature over the provided message using SHA-512/265 with a domain separator.
        /// Can be used to sign transactions for the Oasis consensus layer and SDK paratimes.
        Ed25519Oasis,
        /// Ed25519 signature over the provided message.
        Ed25519Pure,
        /// Ed25519 signature over the provided prehashed SHA-512 digest.
        Ed25519PrehashedSha512,
        /// Secp256k1 signature over the provided message using SHA-512/256 with a domain separator.
        /// Can be used to sign transactions for the Oasis consensus layer and SDK paratimes.
        Secp256k1Oasis,
        /// Secp256k1 over the provided Keccak256 digest.
        /// Can be used to sign transactions for Ethereum-compatible networks.
        Secp256k1PrehashedKeccak256,
        /// Secp256k1 signature over the provided SHA-256 digest.
        Secp256k1PrehashedSha256,
        /// Sr25519 signature over the provided message.
        Sr25519,
        /// Secp256r1 signature over the provided SHA-256 digest.
        Secp256r1PrehashedSha256,
        /// Secp384r1 signature over the provided SHA-384 digest.
        Secp384r1PrehashedSha384
    }
   
    function randomBytes(uint256 numBytes, bytes memory pers)
        internal
        view
        returns (bytes memory)
    {
        (bool success, bytes memory entropy) = RANDOM_BYTES.staticcall(
            abi.encode(numBytes, pers)
        );
        require(success, "randomBytes: failed");
        return entropy;
    }
    function generateCurve25519KeyPair(bytes memory pers)
        internal
        view
        returns (Curve25519PublicKey pk, Curve25519SecretKey sk)
    {
        bytes memory scalar = randomBytes(32, pers);
        // Twiddle some bits, as per RFC 7748 §5.
        scalar[0] &= 0xf8; // Make it a multiple of 8 to avoid small subgroup attacks.
        scalar[31] &= 0x7f; // Clamp to < 2^255 - 19
        scalar[31] |= 0x40; // Clamp to >= 2^254
        (bool success, bytes memory pkBytes) = CURVE25519_PUBLIC_KEY.staticcall(
            scalar
        );
        require(success, "gen curve25519 pk: failed");
        return (
            Curve25519PublicKey.wrap(bytes32(pkBytes)),
            Curve25519SecretKey.wrap(bytes32(scalar))
        );
    }

    function deriveSymmetricKey(
        Curve25519PublicKey peerPublicKey,
        Curve25519SecretKey secretKey
    ) internal view returns (bytes32) {
        (bool success, bytes memory symmetric) = DERIVE_KEY.staticcall(
            abi.encode(peerPublicKey, secretKey)
        );
        require(success, "deriveSymmetricKey: failed");
        return bytes32(symmetric);
    }

    function encrypt(
        bytes32 key,
        bytes32 nonce,
        bytes memory plaintext,
        bytes memory additionalData
    ) internal view returns (bytes memory) {
        (bool success, bytes memory ciphertext) = ENCRYPT.staticcall(
            abi.encode(key, nonce, plaintext, additionalData)
        );
        require(success, "encrypt: failed");
        return ciphertext;
    }
    function decrypt(
        bytes32 key,
        bytes32 nonce,
        bytes memory ciphertext,
        bytes memory additionalData
    ) internal view returns (bytes memory) {
        (bool success, bytes memory plaintext) = DECRYPT.staticcall(
            abi.encode(key, nonce, ciphertext, additionalData)
        );
        require(success, "decrypt: failed");
        return plaintext;
    }
    
    function generateSigningKeyPair(SigningAlg alg, bytes memory seed)
        internal
        view
        returns (bytes memory publicKey, bytes memory secretKey)
    {
        (bool success, bytes memory keypair) = GENERATE_SIGNING_KEYPAIR
            .staticcall(abi.encode(alg, seed));
        require(success, "gen signing keypair: failed");
        return abi.decode(keypair, (bytes, bytes));
    }
    function sign(
        SigningAlg alg,
        bytes memory secretKey,
        bytes memory contextOrHash,
        bytes memory message
    ) internal view returns (bytes memory signature) {
        (bool success, bytes memory sig) = SIGN_DIGEST.staticcall(
            abi.encode(alg, secretKey, contextOrHash, message)
        );
        require(success, "sign: failed");
        return sig;
    }
  
    function verify(
        SigningAlg alg,
        bytes memory publicKey,
        bytes memory contextOrHash,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool verified) {
        (bool success, bytes memory v) = VERIFY_DIGEST.staticcall(
            abi.encode(alg, publicKey, contextOrHash, message, signature)
        );
        require(success, "verify: failed");
        return abi.decode(v, (bool));
    }

    
    function padGas(uint128 toAmount) internal view {
        (bool success, ) = PAD_GAS.staticcall(abi.encode(toAmount));
        require(success, "verify: failed");
    }

   
    function gasUsed() internal view returns (uint64) {
        (bool success, bytes memory v) = GAS_USED.staticcall("");
        require(success, "gasused: failed");
        return abi.decode(v, (uint64));
    }
}


function sha512_256(bytes memory input) view returns (bytes32 result) {
    (bool success, bytes memory output) = Sapphire.SHA512_256.staticcall(input);

    require(success, "sha512_256");

    return bytes32(output);
}


function sha512(bytes memory input) view returns (bytes memory output) {
    bool success;

    (success, output) = Sapphire.SHA512.staticcall(input);

    require(success, "sha512");
}

function sha384(bytes memory input) view returns (bytes memory output) {
    bool success;

    (success, output) = Sapphire.SHA384.staticcall(input);

    require(success, "sha384");
}`,
  },
  "@oasisprotocol/sapphire-contracts/contracts/EthereumUtils.sol": {
    content: `// SPDX-License-Identifier: Apache-2.0

    pragma solidity ^0.8.0;

    import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";

    struct SignatureRSV {
        bytes32 r;
        bytes32 s;
        uint256 v;
        }
    }

library EthereumUtils {
    uint256 internal constant K256_P =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

    // (p+1)//4
    uint256 internal constant K256_P_PLUS_1_OVER_4 =
        0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c;

    address internal constant PRECOMPILE_BIGMODEXP = address(0x5);

    error expmod_Error();

    function expmod(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) internal view returns (uint256 out) {
        (bool success, bytes memory result) = PRECOMPILE_BIGMODEXP.staticcall(
            abi.encodePacked(
                uint256(0x20), // length of base
                uint256(0x20), // length of exponent
                uint256(0x20), // length of modulus
                base,
                exponent,
                modulus
            )
        );

        if (!success) revert expmod_Error();

        out = uint256(bytes32(result));
    }

    error k256DeriveY_Invalid_Prefix_Error();

    function k256DeriveY(uint8 prefix, uint256 x)
        internal
        view
        returns (uint256 y)
    {
        if (prefix != 0x02 && prefix != 0x03)
            revert k256DeriveY_Invalid_Prefix_Error();

        // x^3 + ax + b, where a=0, b=7
        y = addmod(mulmod(x, mulmod(x, x, K256_P), K256_P), 7, K256_P);

        // find square root of quadratic residue
        y = expmod(y, K256_P_PLUS_1_OVER_4, K256_P);

        // negate y if indicated by sign bit
        if ((y + prefix) % 2 != 0) {
            y = K256_P - y;
        }
    }

    error k256Decompress_Invalid_Length_Error();

    /**
     * @notice Decompress SEC P256 k1 point.
     * @param pk 33 byte compressed public key.
     * @return x X coordinate.
     * @return y Y coordinate.
     */
    function k256Decompress(bytes memory pk)
        internal
        view
        returns (uint256 x, uint256 y)
    {
        if (pk.length != 33) revert k256Decompress_Invalid_Length_Error();
        assembly {
            // skip 32 byte length prefix, plus one byte sign prefix
            x := mload(add(pk, 33))
        }
        y = k256DeriveY(uint8(pk[0]), x);
    }

    function k256PubkeyToEthereumAddress(bytes memory pubkey)
        internal
        view
        returns (address)
    {
        (uint256 x, uint256 y) = k256Decompress(pubkey);
        return toEthereumAddress(x, y);
    }

    /**
     * @notice Convert SEC P256 k1 curve point to Ethereum address.
     * @param x X coordinate.
     * @param y Y coordinate.
     * @custom:see https://gavwood.com/paper.pdf (pp. 212)
     */
    function toEthereumAddress(uint256 x, uint256 y)
        internal
        pure
        returns (address)
    {
        bytes32 digest = keccak256(abi.encodePacked(x, y));

        return address(uint160((uint256(digest) << 96) >> 96));
    }

    error DER_Split_Error();

    function splitDERSignature(bytes memory der)
        internal
        pure
        returns (SignatureRSV memory rsv)
    {
        if (der.length < 8) revert DER_Split_Error();
        if (der[0] != 0x30) revert DER_Split_Error();
        if (der[2] != 0x02) revert DER_Split_Error();

        uint256 zLen = uint8(der[1]);
        uint256 rLen = uint8(der[3]);
        if (rLen > 33) revert DER_Split_Error();

        uint256 sOffset = 4 + rLen;
        uint256 sLen = uint8(der[sOffset + 1]);
        if (sLen > 33) revert DER_Split_Error();
        if (der[sOffset] != 0x02) revert DER_Split_Error();

        if (rLen + sLen + 4 != zLen) revert DER_Split_Error();
        if (der.length != zLen + 2) revert DER_Split_Error();

        sOffset += 2;
        uint256 rOffset = 4;

        if (rLen == 33) {
            if (der[4] != 0x00) revert DER_Split_Error();
            rOffset += 1;
            rLen -= 1;
        }

        if (sLen == 33) {
            if (der[sOffset] != 0x00) revert DER_Split_Error();
            sOffset += 1;
            sLen -= 1;
        }

        bytes32 r;
        bytes32 s;

        assembly {
            r := mload(add(der, add(32, rOffset)))
            s := mload(add(der, add(32, sOffset)))
        }

        if (rLen < 32) {
            r >>= 8 * (32 - rLen);
        }

        if (sLen < 32) {
            s >>= 8 * (32 - sLen);
        }

        rsv.r = r;
        rsv.s = s;
    }

    error recoverV_Error();

    function recoverV(
        address pubkeyAddr,
        bytes32 digest,
        SignatureRSV memory rsv
    ) internal pure {
        rsv.v = 27;

        if (ecrecover(digest, uint8(rsv.v), rsv.r, rsv.s) != pubkeyAddr) {
            rsv.v = 28;

            if (ecrecover(digest, uint8(rsv.v), rsv.r, rsv.s) != pubkeyAddr) {
                revert recoverV_Error();
            }
        }
    }
    function toEthereumSignature(
        bytes memory pubkey,
        bytes32 digest,
        bytes memory signature
    ) internal view returns (address pubkeyAddr, SignatureRSV memory rsv) {
        pubkeyAddr = k256PubkeyToEthereumAddress(pubkey);

        rsv = splitDERSignature(signature);

        recoverV(pubkeyAddr, digest, rsv);
    }

    function sign(
        address pubkeyAddr,
        bytes32 secretKey,
        bytes32 digest
    ) internal view returns (SignatureRSV memory rsv) {
        bytes memory signature = Sapphire.sign(
            Sapphire.SigningAlg.Secp256k1PrehashedKeccak256,
            abi.encodePacked(secretKey),
            abi.encodePacked(digest),
            ""
        );

        rsv = splitDERSignature(signature);

        recoverV(pubkeyAddr, digest, rsv);
    }
    function generateKeypair()
        internal
        view
        returns (address pubkeyAddr, bytes32 secretKey)
    {
        bytes memory randSeed = Sapphire.randomBytes(32, "");

        secretKey = bytes32(randSeed);

        (bytes memory pk, ) = Sapphire.generateSigningKeyPair(
            Sapphire.SigningAlg.Secp256k1PrehashedKeccak256,
            randSeed
        );

        pubkeyAddr = k256PubkeyToEthereumAddress(pk);
    }
}`,
  },
  "@openzeppelin/contracts/utils/Strings.sol":{
    content:`pragma solidity ^0.8.20;

    import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
    import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
    import {SignedMath} from "@openzeppelin/contracts/utils/math/SignedMath.sol";

    library Strings {
        using SafeCast for *;

    bytes16 private constant HEX_DIGITS = "0123456789abcdef";
    uint8 private constant ADDRESS_LENGTH = 20;
    uint256 private constant SPECIAL_CHARS_LOOKUP =
        (1 << 0x08) |
            (1 << 0x09) |
            (1 << 0x0a) |
            (1 << 0x0c) |
            (1 << 0x0d) |
            (1 << 0x22) |
            (1 << 0x5c);

    error StringsInsufficientHexLength(uint256 value, uint256 length);
    error StringsInvalidChar();
    error StringsInvalidAddressFormat();

    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            assembly ("memory-safe") {
                ptr := add(add(buffer, 0x20), length)
            }
            while (true) {
                ptr--;
                assembly ("memory-safe") {
                    mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    function toStringSigned(int256 value) internal pure returns (string memory) {
        return string.concat(value < 0 ? "-" : "", toString(SignedMath.abs(value)));
    }

    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        uint256 localValue = value;
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = HEX_DIGITS[localValue & 0xf];
            localValue >>= 4;
        }
        if (localValue != 0) {
            revert StringsInsufficientHexLength(value, length);
        }
        return string(buffer);
    }

    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), ADDRESS_LENGTH);
    }

    function toChecksumHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = bytes(toHexString(addr));

        uint256 hashValue;
        assembly ("memory-safe") {
            hashValue := shr(96, keccak256(add(buffer, 0x22), 40))
        }

        for (uint256 i = 41; i > 1; --i) {
            if (hashValue & 0xf > 7 && uint8(buffer[i]) > 96) {
                buffer[i] ^= 0x20;
            }
            hashValue >>= 4;
        }
        return string(buffer);
    }

    function equal(string memory a, string memory b) internal pure returns (bool) {
        return bytes(a).length == bytes(b).length && keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function parseUint(string memory input) internal pure returns (uint256) {
        return parseUint(input, 0, bytes(input).length);
    }

    function parseUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    function tryParseUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseUintUncheckedBounds(input, 0, bytes(input).length);
    }

    function tryParseUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseUintUncheckedBounds(input, begin, end);
    }

    function _tryParseUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        uint256 result = 0;
        for (uint256 i = begin; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 9) return (false, 0);
            result *= 10;
            result += chr;
        }
        return (true, result);
    }

    function parseInt(string memory input) internal pure returns (int256) {
        return parseInt(input, 0, bytes(input).length);
    }

    function parseInt(string memory input, uint256 begin, uint256 end) internal pure returns (int256) {
        (bool success, int256 value) = tryParseInt(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    function tryParseInt(string memory input) internal pure returns (bool success, int256 value) {
        return _tryParseIntUncheckedBounds(input, 0, bytes(input).length);
    }

    uint256 private constant ABS_MIN_INT256 = 2 ** 255;

    function tryParseInt(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, int256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseIntUncheckedBounds(input, begin, end);
    }

    function _tryParseIntUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, int256 value) {
        bytes memory buffer = bytes(input);

        bytes1 sign = begin == end ? bytes1(0) : bytes1(_unsafeReadBytesOffset(buffer, begin));
        bool positiveSign = sign == bytes1("+");
        bool negativeSign = sign == bytes1("-");
        uint256 offset = (positiveSign || negativeSign).toUint();

        (bool absSuccess, uint256 absValue) = tryParseUint(input, begin + offset, end);

        if (absSuccess && absValue < ABS_MIN_INT256) {
            return (true, negativeSign ? -int256(absValue) : int256(absValue));
        } else if (absSuccess && negativeSign && absValue == ABS_MIN_INT256) {
            return (true, type(int256).min);
        } else return (false, 0);
    }

    function parseHexUint(string memory input) internal pure returns (uint256) {
        return parseHexUint(input, 0, bytes(input).length);
    }

    function parseHexUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseHexUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    function tryParseHexUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseHexUintUncheckedBounds(input, 0, bytes(input).length);
    }

    function tryParseHexUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseHexUintUncheckedBounds(input, begin, end);
    }

    function _tryParseHexUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(buffer, begin)) == bytes2("0x");
        uint256 offset = hasPrefix.toUint() * 2;

        uint256 result = 0;
        for (uint256 i = begin + offset; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 15) return (false, 0);
            result *= 16;
            unchecked {
                result += chr;
            }
        }
        return (true, result);
    }

    function parseAddress(string memory input) internal pure returns (address) {
        return parseAddress(input, 0, bytes(input).length);
    }

    function parseAddress(string memory input, uint256 begin, uint256 end) internal pure returns (address) {
        (bool success, address value) = tryParseAddress(input, begin, end);
        if (!success) revert StringsInvalidAddressFormat();
        return value;
    }

    function tryParseAddress(string memory input) internal pure returns (bool success, address value) {
        return tryParseAddress(input, 0, bytes(input).length);
    }

    function tryParseAddress(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, address value) {
        if (end > bytes(input).length || begin > end) return (false, address(0));

        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(bytes(input), begin)) == bytes2("0x");
        uint256 expectedLength = 40 + hasPrefix.toUint() * 2;

        if (end - begin == expectedLength) {
            (bool s, uint256 v) = _tryParseHexUintUncheckedBounds(input, begin, end);
            return (s, address(uint160(v)));
        } else {
            return (false, address(0));
        }
    }

    function _tryParseChr(bytes1 chr) private pure returns (uint8) {
        uint8 value = uint8(chr);

        unchecked {
            if (value > 47 && value < 58) value -= 48;
            else if (value > 96 && value < 103) value -= 87;
            else if (value > 64 && value < 71) value -= 55;
            else return type(uint8).max;
        }

        return value;
    }

    function escapeJSON(string memory input) internal pure returns (string memory) {
        bytes memory buffer = bytes(input);
        bytes memory output = new bytes(2 * buffer.length);
        uint256 outputLength = 0;

        for (uint256 i; i < buffer.length; ++i) {
            bytes1 char = bytes1(_unsafeReadBytesOffset(buffer, i));
            if (((SPECIAL_CHARS_LOOKUP & (1 << uint8(char))) != 0)) {
                output[outputLength++] = "\\\\";
                if (char == 0x08) output[outputLength++] = "b";
                else if (char == 0x09) output[outputLength++] = "t";
                else if (char == 0x0a) output[outputLength++] = "n";
                else if (char == 0x0c) output[outputLength++] = "f";
                else if (char == 0x0d) output[outputLength++] = "r";
                else if (char == 0x5c) output[outputLength++] = "\\\\";
                else if (char == 0x22) {
                    output[outputLength++] = '"';
                }
            } else {
                output[outputLength++] = char;
            }
        }
        assembly ("memory-safe") {
            mstore(output, outputLength)
            mstore(0x40, add(output, shl(5, shr(5, add(outputLength, 63)))))
        }

        return string(output);
    }

    function _unsafeReadBytesOffset(bytes memory buffer, uint256 offset) private pure returns (bytes32 value) {
        assembly ("memory-safe") {
            value := mload(add(add(buffer, 0x20), offset))
        }
    }
}`
  },
  "@openzeppelin/contracts/utils/math/Math.sol":{
    content:`pragma solidity ^0.8.20;

    import {Panic} from "@openzeppelin/contracts/utils/Panic.sol";
    import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

library Math {
    enum Rounding {
        Floor,
        Ceil,
        Trunc,
        Expand
    }

    function add512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            low := add(a, b)
            high := lt(low, a)
        }
    }

    function mul512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            let mm := mulmod(a, b, not(0))
            low := mul(a, b)
            high := sub(sub(mm, low), lt(mm, low))
        }
    }

    function tryAdd(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a + b;
            success = c >= a;
            result = c * SafeCast.toUint(success);
        }
    }

    function trySub(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a - b;
            success = c <= a;
            result = c * SafeCast.toUint(success);
        }
    }

    function tryMul(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a * b;
            assembly ("memory-safe") {
                success := or(eq(div(c, a), b), iszero(a))
            }
            result = c * SafeCast.toUint(success);
        }
    }

    function tryDiv(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                result := div(a, b)
            }
        }
    }

    function tryMod(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                result := mod(a, b)
            }
        }
    }

    function saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryAdd(a, b);
        return ternary(success, result, type(uint256).max);
    }

    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        (, uint256 result) = trySub(a, b);
        return result;
    }

    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryMul(a, b);
        return ternary(success, result, type(uint256).max);
    }

    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return b ^ ((a ^ b) * SafeCast.toUint(condition));
        }
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a > b, a, b);
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a < b, a, b);
    }

    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a & b) + (a ^ b) / 2;
    }

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        unchecked {
            return SafeCast.toUint(a > 0) * ((a - 1) / b + 1);
        }
    }

    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);

            if (high == 0) {
                return low / denominator;
            }

            if (denominator <= high) {
                Panic.panic(ternary(denominator == 0, Panic.DIVISION_BY_ZERO, Panic.UNDER_OVERFLOW));
            }

            uint256 remainder;
            assembly ("memory-safe") {
                remainder := mulmod(x, y, denominator)
                high := sub(high, gt(remainder, low))
                low := sub(low, remainder)
            }

            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                denominator := div(denominator, twos)
                low := div(low, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }

            low |= high * twos;

            uint256 inverse = (3 * denominator) ^ 2;

            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;

            result = low * inverse;
            return result;
        }
    }

    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        return mulDiv(x, y, denominator) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0);
    }

    function mulShr(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);
            if (high >= 1 << n) {
                Panic.panic(Panic.UNDER_OVERFLOW);
            }
            return (high << (256 - n)) | (low >> n);
        }
    }

    function mulShr(uint256 x, uint256 y, uint8 n, Rounding rounding) internal pure returns (uint256) {
        return mulShr(x, y, n) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, 1 << n) > 0);
    }

    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            uint256 remainder = a % n;
            uint256 gcd = n;

            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    remainder,
                    gcd - remainder * quotient
                );

                (x, y) = (
                    y,
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0;
            return ternary(x < 0, n - uint256(-x), uint256(x));
        }
    }

    function invModPrime(uint256 a, uint256 p) internal view returns (uint256) {
        unchecked {
            return Math.modExp(a, p - 2, p);
        }
    }

    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256) {
        (bool success, uint256 result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    function tryModExp(uint256 b, uint256 e, uint256 m) internal view returns (bool success, uint256 result) {
        if (m == 0) return (false, 0);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)

            success := staticcall(gas(), 0x05, ptr, 0xc0, 0x00, 0x20)
            result := mload(0x00)
        }
    }

    function modExp(bytes memory b, bytes memory e, bytes memory m) internal view returns (bytes memory) {
        (bool success, bytes memory result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    function tryModExp(
        bytes memory b,
        bytes memory e,
        bytes memory m
    ) internal view returns (bool success, bytes memory result) {
        if (_zeroBytes(m)) return (false, new bytes(0));

        uint256 mLen = m.length;

        result = abi.encodePacked(b.length, e.length, mLen, b, e, m);

        assembly ("memory-safe") {
            let dataPtr := add(result, 0x20)
            success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            mstore(result, mLen)
            mstore(0x40, add(dataPtr, mLen))
        }
    }

    function _zeroBytes(bytes memory byteArray) private pure returns (bool) {
        for (uint256 i = 0; i < byteArray.length; ++i) {
            if (byteArray[i] != 0) {
                return false;
            }
        }
        return true;
    }

    function sqrt(uint256 a) internal pure returns (uint256) {
        unchecked {
            if (a <= 1) {
                return a;
            }

            uint256 aa = a;
            uint256 xn = 1;

            if (aa >= (1 << 128)) {
                aa >>= 128;
                xn <<= 64;
            }
            if (aa >= (1 << 64)) {
                aa >>= 64;
                xn <<= 32;
            }
            if (aa >= (1 << 32)) {
                aa >>= 32;
                xn <<= 16;
            }
            if (aa >= (1 << 16)) {
                aa >>= 16;
                xn <<= 8;
            }
            if (aa >= (1 << 8)) {
                aa >>= 8;
                xn <<= 4;
            }
            if (aa >= (1 << 4)) {
                aa >>= 4;
                xn <<= 2;
            }
            if (aa >= (1 << 2)) {
                xn <<= 1;
            }

            xn = (3 * xn) >> 1;

            xn = (xn + a / xn) >> 1;
            xn = (xn + a / xn) >> 1;
            xn = (xn + a / xn) >> 1;
            xn = (xn + a / xn) >> 1;
            xn = (xn + a / xn) >> 1;
            xn = (xn + a / xn) >> 1;

            return xn - SafeCast.toUint(xn > a / xn);
        }
    }

    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && result * result < a);
        }
    }

    function log2(uint256 x) internal pure returns (uint256 r) {
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        r |= SafeCast.toUint((x >> r) > 0xff) << 3;
        r |= SafeCast.toUint((x >> r) > 0xf) << 2;

        assembly ("memory-safe") {
            r := or(r, byte(shr(r, x), 0x0000010102020202030303030303030300000000000000000000000000000000))
        }
    }

    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << result < value);
        }
    }

    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 10 ** result < value);
        }
    }

    function log256(uint256 x) internal pure returns (uint256 r) {
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        return (r >> 3) | SafeCast.toUint((x >> r) > 0xff);
    }

    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << (result << 3) < value);
        }
    }

    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
}`
  },
  "@openzeppelin/contracts/utils/math/SafeCast.sol":{
    content:`pragma solidity ^0.8.20;

library SafeCast {
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);
    error SafeCastOverflowedIntToUint(int256 value);
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);
    error SafeCastOverflowedUintToInt(uint256 value);

    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    function toInt256(uint256 value) internal pure returns (int256) {
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }

    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }
}`
  },
  "@openzeppelin/contracts/utils/math/SignedMath.sol":{
    content:`pragma solidity ^0.8.20;

    import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

    library SignedMath {
        function ternary(bool condition, int256 a, int256 b) internal pure returns (int256) {
            unchecked {
                return b ^ ((a ^ b) * int256(SafeCast.toUint(condition)));
            }
        }

    function max(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a > b, a, b);
    }

    function min(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a < b, a, b);
    }

    function average(int256 a, int256 b) internal pure returns (int256) {
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            int256 mask = n >> 255;
            return uint256((n + mask) ^ mask);
        }
    }
    }`,
  },
  "@openzeppelin/contracts/utils/Panic.sol":{
    content:`pragma solidity ^0.8.20;

    library Panic {
    uint256 internal constant GENERIC = 0x00;
    uint256 internal constant ASSERT = 0x01;
    uint256 internal constant UNDER_OVERFLOW = 0x11;
    uint256 internal constant DIVISION_BY_ZERO = 0x12;
    uint256 internal constant ENUM_CONVERSION_ERROR = 0x21;
    uint256 internal constant STORAGE_ENCODING_ERROR = 0x22;
    uint256 internal constant EMPTY_ARRAY_POP = 0x31;
    uint256 internal constant ARRAY_OUT_OF_BOUNDS = 0x32;
    uint256 internal constant RESOURCE_ERROR = 0x41;
    uint256 internal constant INVALID_INTERNAL_FUNCTION = 0x51;

    function panic(uint256 code) internal pure {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }
}`
  },
};

export const extractDependencies = (solidityCode: string) => {
  const importRegex = /import\s+(?:{[^}]+}\s+from\s+)?["']([^"']+)["'];/g;
  const requiredDependencies: Record<string, { content: string }> = {};
  const visitedPaths = new Set<string>();

  const processFile = (code: string, filePath: string) => {
    if (visitedPaths.has(filePath)) return;
    visitedPaths.add(filePath);

    let match: RegExpExecArray | null;
    while ((match = importRegex.exec(code)) !== null) {
      const importPath = match[1].trim();


      const normalizedPath = importPath.replace(/^\.\//, "");

      if (dependencySources[normalizedPath]) {
        if (!requiredDependencies[normalizedPath]) {
          requiredDependencies[normalizedPath] = dependencySources[normalizedPath];
          processFile(dependencySources[normalizedPath].content, normalizedPath);
        }
      } else {
        console.error(`Missing dependency for: ${normalizedPath}`);
      }
    }
  };

  // Start processing from the main contract with modified code
  processFile(solidityCode, "contract.sol");

  // Store the modified code in dependencies
  requiredDependencies["contract.sol"] = { content: solidityCode };

  console.log("Final dependencies:", Object.keys(requiredDependencies));
  return requiredDependencies;
};

export const compileContract = async (solidityCode: string) => {
  return new Promise<{
    bytecode: string;
    abi: any;
    contractName: string;
    dependencies: Record<string, { content: string }>;
  }>((resolve, reject) => {
    const requiredDependencies = extractDependencies(solidityCode);
    const worker = new Worker(new URL("../solc-worker.js", import.meta.url));

    worker.onmessage = event => {
      const { output, error } = event.data;
      if (error) {
        reject(new Error(`Compilation error: ${error}`));
        worker.terminate();
        return;
      }

      const contractName = Object.keys(output.contracts["contract.sol"])[0];
      const compiledContract = output.contracts["contract.sol"][contractName];
      resolve({
        bytecode: compiledContract.evm.bytecode.object,
        abi: compiledContract.abi,
        contractName: contractName,
        dependencies: requiredDependencies,
      });

      worker.terminate();
    };

    worker.onerror = event => {
      reject(new Error(`Worker error: ${event.message || "Unknown error"}`));
      worker.terminate();
    };

    worker.postMessage({
      code: solidityCode,
      dependencySources: requiredDependencies,
    });
  });
};

export const compileTAContract = async (solidityCode: string) => {
  return new Promise<{ bytecode: string; abi: any }>((resolve, reject) => {
    const requiredDependencies = extractDependencies(solidityCode);
    const worker = new Worker(new URL("../solc-worker-ta.js", import.meta.url));

    worker.onmessage = event => {
      const { output, error } = event.data;
      if (error) {
        reject(new Error(`Compilation error: ${error}`));
        worker.terminate();
        return;
      }

      const contractName = Object.keys(output.contracts["contract.sol"])[0];
      const compiledContract = output.contracts["contract.sol"][contractName];
      resolve({
        bytecode: compiledContract.evm.bytecode.object,
        abi: compiledContract.abi,
      });

      worker.terminate();
    };

    worker.onerror = event => {
      reject(new Error(`Worker error: ${event.message || "Unknown error"}`));
      worker.terminate();
    };

    worker.postMessage({
      code: solidityCode,
      dependencySources: requiredDependencies,
    });
  });
};
