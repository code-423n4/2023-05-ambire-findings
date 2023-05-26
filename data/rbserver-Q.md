## QA REPORT

| |Issue|
|-|:-|
| [01] | CALLERS OF `AmbireAccount.execute` FUNCTION CAN RACE TO INCREASE `nonce` |
| [02] | SCHEDULED RECOVERY TRANSACTION CAN STILL BE CANCELED AFTER SCHEDULED TIME IS REACHED |
| [03] | `AmbireAccount.executeBySender` FUNCTION CAN BE REENTERED |
| [04] | `AmbireAccountFactory.deploySafe` FUNCTION CAN CAUSE DEPLOYER TO EXECUTE ACCIDENTAL TRANSACTIONS |
| [05] | CALLING `AmbireAccount.execute` FUNCTION WITH SAME SIGNATURE FOR CANCELING A SCHEDULED RECOVERY TRANSACTION FOR MANY TIMES CAN CAUSE EVENT LOG POISONING |
| [06] | `AmbireAccount` CONTRACT'S CONSTRUCTOR DOES NOT CHECK IF `addrs.length` IS 0 OR `addrs[i]` IS `address(0)` |
| [07] | MISSING `address(0)` CHECK FOR `allowed` IN `AmbireAccountFactory` CONTRACT'S CONSTRUCTOR |
| [08] | `SignatureValidator.recoverAddrImpl` FUNCTION ALLOWS SPOOFING WHEN `tx.origin == address(6969)` IS TRUE |
| [09] | `SignatureValidator.recoverAddrImpl` DOES NOT CHECK FOR SIGNATURE MALLEABILITY |
| [10] | `SignatureValidator.splitSignature` FUNCTION DOES NOT EXECUTE `require(sig.length != 0, 'SV_SIGLEN')` |
| [11] | `Bytes.trimToSize` FUNCTION CAN TRIM `b`'S LENGTH TO 0 |
| [12] | MISSING REASON STRINGS IN `require` STATEMENTS |
| [13] | `AmbireAccount.onERC721Received`, `AmbireAccount.onERC1155Received`, AND `AmbireAccount.onERC1155BatchReceived` FUNCTIONS CAN EMIT IMPORTANT EVENTS |
| [14] | `require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL')` CAN BE REFACTORED INTO A MODIFIER TO BE USED IN RESPECTIVE FUNCTIONS |
| [15] | REDUNDANT RETURN STATEMENT FOR `readBytes32` FUNCTION, WHICH HAS NAMED RETURN, CAN BE REMOVED |
| [16] | `uint256` CAN BE USED INSTEAD OF `uint` |
| [17] | WORD TYPING TYPO |
| [18] | `AmbireAccount.executeMultiple` FUNCTION CAN HAVE CODE ON A SEPARATE LINE |
| [19] | INCOMPLETE NATSPEC COMMENTS |
| [20] | MISSING NATSPEC COMMENTS |

## [01] CALLERS OF `AmbireAccount.execute` FUNCTION CAN RACE TO INCREASE `nonce`
When the following `AmbireAccount.execute` function is called to execute `txns`, `nonce` is increased. When multiple valid signatures are all based on the same `nonce`, increasing `nonce` means that only one of these signatures can be used to execute the corresponding `txns`. In this case, one caller of the `AmbireAccount.execute` function would be encouraged to frontrun the other callers' `AmbireAccount.execute` function calls to ensure its `txns` can be executed, and the other callers' `AmbireAccount.execute` function calls would then revert unexpectedly after such frontrunning. Similarly, when there is a scheduled recovery transaction, calling the `AmbireAccount.execute` function to execute a normal transaction would increase `nonce`; afterwards, `hash` can no longer be constructed to correspond to such scheduled recovery transaction since `currentNonce` has been increased already, and such scheduled recovery transaction can never be executed or canceled. If wanting to allow such scheduled recovery transaction to be executed or canceled properly, the caller for the normal transaction must wait until the scheduled recovery transaction is executed or canceled before calling the `AmbireAccount.execute` function for its own normal transaction, which can be very inconvenient because the locked time for the scheduled recovery transaction can be long. To avoid these situations, please consider updating the `AmbireAccount` contract to keep track of a nonce for each caller of the `AmbireAccount.execute` function and updating the `AmbireAccount.execute` function to use a hash that is based on `address(this)`, `block.chainid`, `txns`, `msg.sender`, and the current nonce for `msg.sender` and increase the nonce for `msg.sender` when `txns` are executed.

https://github.com/AmbireTech/ambire-common/blob/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts/AmbireAccount.sol#L135-L194
```solidity
	function execute(Transaction[] calldata txns, bytes calldata signature) public payable {
		uint256 currentNonce = nonce;
		// NOTE: abi.encode is safer than abi.encodePacked in terms of collision safety
		bytes32 hash = keccak256(abi.encode(address(this), block.chainid, currentNonce, txns));

		address signerKey;
		// Recovery signature: allows to perform timelocked txns
		uint8 sigMode = uint8(signature[signature.length - 1]);

		if (sigMode == SIGMODE_RECOVER || sigMode == SIGMODE_CANCEL) {
			...

			uint256 scheduled = scheduledRecoveries[hash];
			if (scheduled != 0 && !isCancellation) {
				require(block.timestamp > scheduled, 'RECOVERY_NOT_READY');
				delete scheduledRecoveries[hash];
				emit LogRecoveryFinalized(hash, recoveryInfoHash, block.timestamp);
			} else {
				...
			}
		} else {
			...
		}

		// we increment the nonce to prevent reentrancy
		// also, we do it here as we want to reuse the previous nonce
		// and respectively hash upon recovery / canceling
		// doing this after sig verification is fine because sig verification can only do STATICCALLS
		nonce = currentNonce + 1;
		executeBatch(txns);

		...
	}
```

## [02] SCHEDULED RECOVERY TRANSACTION CAN STILL BE CANCELED AFTER SCHEDULED TIME IS REACHED
When the scheduled time for a scheduled recovery transaction is reached, such recovery transaction can be executed. Yet, if one of `recoveryInfo.keys` becomes compromised at that time, it can frontrun the `AmbireAccount.execute` function call that would execute the scheduled recovery transaction by calling the `AmbireAccount.execute` function through using a signature for canceling such recovery transaction even if `block.timestamp > scheduled` is already true. This is unfair to the scheduled recovery transaction because it has passed the locked time already. Since a reasonable locked time for a scheduled recovery transaction should be long enough for canceling such scheduled transaction if needed, please consider updating the `AmbireAccount.execute` function to make the scheduled recovery transaction only cancelable before the scheduled time is reached.

https://github.com/AmbireTech/ambire-common/blob/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts/AmbireAccount.sol#L135-L194
```solidity
	function execute(Transaction[] calldata txns, bytes calldata signature) public payable {
		...

		if (sigMode == SIGMODE_RECOVER || sigMode == SIGMODE_CANCEL) {
			(bytes memory sig, ) = SignatureValidator.splitSignature(signature);
			(RecoveryInfo memory recoveryInfo, bytes memory innerRecoverySig, address signerKeyToRecover) = abi.decode(
				sig,
				(RecoveryInfo, bytes, address)
			);
			signerKey = signerKeyToRecover;
			bool isCancellation = sigMode == SIGMODE_CANCEL;
			bytes32 recoveryInfoHash = keccak256(abi.encode(recoveryInfo));
			require(privileges[signerKeyToRecover] == recoveryInfoHash, 'RECOVERY_NOT_AUTHORIZED');

			uint256 scheduled = scheduledRecoveries[hash];
			if (scheduled != 0 && !isCancellation) {
				require(block.timestamp > scheduled, 'RECOVERY_NOT_READY');
				delete scheduledRecoveries[hash];
				emit LogRecoveryFinalized(hash, recoveryInfoHash, block.timestamp);
			} else {
				bytes32 hashToSign = isCancellation ? keccak256(abi.encode(hash, 0x63616E63)) : hash;
				address recoveryKey = SignatureValidator.recoverAddrImpl(hashToSign, innerRecoverySig, true);
				bool isIn;
				for (uint256 i = 0; i < recoveryInfo.keys.length; i++) {
					if (recoveryInfo.keys[i] == recoveryKey) {
						isIn = true;
						break;
					}
				}
				require(isIn, 'RECOVERY_NOT_AUTHORIZED');
				if (isCancellation) {
					delete scheduledRecoveries[hash];
					emit LogRecoveryCancelled(hash, recoveryInfoHash, recoveryKey, block.timestamp);
				} else {
					scheduledRecoveries[hash] = block.timestamp + recoveryInfo.timelock;
					emit LogRecoveryScheduled(hash, recoveryInfoHash, recoveryKey, currentNonce, block.timestamp, txns);
				}
				return;
			}
		} else {
			signerKey = SignatureValidator.recoverAddrImpl(hash, signature, true);
			require(privileges[signerKey] != bytes32(0), 'INSUFFICIENT_PRIVILEGE');
		}

		...
	}
```

## [03] `AmbireAccount.executeBySender` FUNCTION CAN BE REENTERED
When calling the following `AmbireAccount.executeBySender` function, the caller might want `txns` to be executed in a specified order. If one of these transactions calls one of the privileged addresses and such privileged address reenters the `AmbireAccount.executeBySender` function, such as if such privileged address has become compromised or malicious, to inject and execute transactions that are not specified by the `AmbireAccount.executeBySender` function's original caller, the intended order of `txns` can be broken, which can lead to unexpected behaviors. To prevent this from happening, please consider updating the `AmbireAccount.executeBySender` function to prevent reentrancy, such as by using a modifier that is similar to OpenZeppelin's `nonReentrant`.

https://github.com/AmbireTech/ambire-common/blob/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts/AmbireAccount.sol#L203-L208
```solidity
	function executeBySender(Transaction[] calldata txns) external payable {
		require(privileges[msg.sender] != bytes32(0), 'INSUFFICIENT_PRIVILEGE');
		executeBatch(txns);
		// again, anti-bricking
		require(privileges[msg.sender] != bytes32(0), 'PRIVILEGE_NOT_DOWNGRADED');
	}
```

## [04] `AmbireAccountFactory.deploySafe` FUNCTION CAN CAUSE DEPLOYER TO EXECUTE ACCIDENTAL TRANSACTIONS
Calling the following `AmbireAccountFactory.deployAndExecute` function would not revert if a contract has been deployed to the expected address corresponding to `code` and `salt` because `size` for `expectedAddr` in this case is not 0 in the `AmbireAccountFactory.deploySafe` function. However, this can cause the deployer to execute accidental transactions. For example, when Alice and Bob already have a deployed account where both have privileges, Alice also wants to deploy her own account and deposit some funds to that account. If Alice accidentally uses the same `code` and `salt` used for the previously mentioned deployed account, calling `AmbireAccountFactory.deployAndExecute` function would not revert and would deposit Alice's funds to such deployed account; then, Bob is able to withdraw Alice's deposited funds from such deployed account, and disputes occur. To prevent such disputes, the `AmbireAccountFactory.deploySafe` function can be updated to revert if a contract has been deployed to `expectedAddr` already; when calling the `AmbireAccountFactory.deploySafe` function reverts, the deployer can double check the `code` and `salt` inputs and whether the contract, which has already been deployed to `expectedAddr`, is the proper account or not for the deployer to interact with.

https://github.com/AmbireTech/ambire-common/blob/8cca47a6f98ea364c3838c1727ff956a00aaa6d2/contracts/AmbireAccountFactory.sol#L24-L32
```solidity
	function deployAndExecute(
		bytes calldata code,
		uint256 salt,
		AmbireAccount.Transaction[] calldata txns,
		bytes calldata signature
	) external {
		address payable addr = payable(deploySafe(code, salt));
		AmbireAccount(addr).execute(txns, signature);
	}
```

https://github.com/AmbireTech/ambire-common/blob/8cca47a6f98ea364c3838c1727ff956a00aaa6d2/contracts/AmbireAccountFactory.sol#L44-L64
```solidity
	function deploySafe(bytes memory code, uint256 salt) internal returns (address) {
		address expectedAddr = address(
			uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(code)))))
		);
		uint256 size;
		assembly {
			size := extcodesize(expectedAddr)
		}
		// If there is code at that address, we can assume it's the one we were about to deploy,
		// because of how CREATE2 and keccak256 works
		if (size == 0) {
			address addr;
			assembly {
				addr := create2(0, add(code, 0x20), mload(code), salt)
			}
			require(addr != address(0), 'FAILED_DEPLOYING');
			require(addr == expectedAddr, 'FAILED_MATCH');
			emit LogDeployed(addr, salt);
		}
		return expectedAddr;
	}
```

## [05] CALLING `AmbireAccount.execute` FUNCTION WITH SAME SIGNATURE FOR CANCELING A SCHEDULED RECOVERY TRANSACTION FOR MANY TIMES CAN CAUSE EVENT LOG POISONING
After calling the following `AmbireAccount.execute` function with `sigMode` being `SIGMODE_CANCEL` to cancel a scheduled recovery, such signature can still be used to call this function for many times as long as `nonce` is not increased. When the scheduled recovery is canceled, the `LogRecoveryCancelled` event should be emitted. However, for the subsequent function calls with the same signature when the corresponding scheduled recovery has already been canceled, these emitted `LogRecoveryCancelled` events are useless and spam the monitor system that consumes such event. To prevent such event log poisoning, please consider also increasing `nonce` when the signature for canceling a scheduled recovery transaction is successfully used.

https://github.com/AmbireTech/ambire-common/blob/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts/AmbireAccount.sol#L135-L194
```solidity
	function execute(Transaction[] calldata txns, bytes calldata signature) public payable {
		...

		if (sigMode == SIGMODE_RECOVER || sigMode == SIGMODE_CANCEL) {
			(bytes memory sig, ) = SignatureValidator.splitSignature(signature);
			(RecoveryInfo memory recoveryInfo, bytes memory innerRecoverySig, address signerKeyToRecover) = abi.decode(
				sig,
				(RecoveryInfo, bytes, address)
			);
			signerKey = signerKeyToRecover;
			bool isCancellation = sigMode == SIGMODE_CANCEL;
			bytes32 recoveryInfoHash = keccak256(abi.encode(recoveryInfo));
			require(privileges[signerKeyToRecover] == recoveryInfoHash, 'RECOVERY_NOT_AUTHORIZED');

			uint256 scheduled = scheduledRecoveries[hash];
			if (scheduled != 0 && !isCancellation) {
				require(block.timestamp > scheduled, 'RECOVERY_NOT_READY');
				delete scheduledRecoveries[hash];
				emit LogRecoveryFinalized(hash, recoveryInfoHash, block.timestamp);
			} else {
				bytes32 hashToSign = isCancellation ? keccak256(abi.encode(hash, 0x63616E63)) : hash;
				address recoveryKey = SignatureValidator.recoverAddrImpl(hashToSign, innerRecoverySig, true);
				bool isIn;
				for (uint256 i = 0; i < recoveryInfo.keys.length; i++) {
					if (recoveryInfo.keys[i] == recoveryKey) {
						isIn = true;
						break;
					}
				}
				require(isIn, 'RECOVERY_NOT_AUTHORIZED');
				if (isCancellation) {
					delete scheduledRecoveries[hash];
					emit LogRecoveryCancelled(hash, recoveryInfoHash, recoveryKey, block.timestamp);
				} else {
					scheduledRecoveries[hash] = block.timestamp + recoveryInfo.timelock;
					emit LogRecoveryScheduled(hash, recoveryInfoHash, recoveryKey, currentNonce, block.timestamp, txns);
				}
				return;
			}
		} else {
			...
		}

		...
	}
```

## [06] `AmbireAccount` CONTRACT'S CONSTRUCTOR DOES NOT CHECK IF `addrs.length` IS 0 OR `addrs[i]` IS `address(0)`
If `addrs` is an empty array or contains only `address(0)` when calling the following constructor for the `AmbireAccount` contract, then the corresponding account would have no privileged addresses. This causes the account to be bricked right after it is created. To avoid this situation, please consider updating this constructor to revert if `addrs.length` is 0 or `addrs[i]` is `address(0)`.

https://github.com/AmbireTech/ambire-common/blob/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts/AmbireAccount.sol#L58-L65
```solidity
	constructor(address[] memory addrs) {
		uint256 len = addrs.length;
		for (uint256 i = 0; i < len; i++) {
			// NOTE: privileges[] can be set to any arbitrary value, but for this we SSTORE directly through the proxy creator
			privileges[addrs[i]] = bytes32(uint(1));
			emit LogPrivilegeChanged(addrs[i], bytes32(uint(1)));
		}
	}
```

## [07] MISSING `address(0)` CHECK FOR `allowed` IN `AmbireAccountFactory` CONTRACT'S CONSTRUCTOR
Since the following `allowedToDrain` is an immutable, the `AmbireAccountFactory.call` function would not be callable if the `AmbireAccountFactory` contract's constructor is called with `allowed` being `address(0)`. To prevent such unexpected behavior, please consider updating this constructor to revert if `allowed` is `address(0)`.

https://github.com/AmbireTech/ambire-common/blob/8cca47a6f98ea364c3838c1727ff956a00aaa6d2/contracts/AmbireAccountFactory.sol#L9
```solidity
	address public immutable allowedToDrain;
```

https://github.com/AmbireTech/ambire-common/blob/8cca47a6f98ea364c3838c1727ff956a00aaa6d2/contracts/AmbireAccountFactory.sol#L11-L13
```solidity
	constructor(address allowed) {
		allowedToDrain = allowed;
	}
```

https://github.com/AmbireTech/ambire-common/blob/8cca47a6f98ea364c3838c1727ff956a00aaa6d2/contracts/AmbireAccountFactory.sol#L35-L39
```solidity
	function call(address to, uint256 value, bytes calldata data, uint256 gas) external {
		require(msg.sender == allowedToDrain, 'ONLY_AUTHORIZED');
		(bool success, bytes memory err) = to.call{ gas: gas, value: value }(data);
		require(success, string(err));
	}
```

## [08] `SignatureValidator.recoverAddrImpl` FUNCTION ALLOWS SPOOFING WHEN `tx.origin == address(6969)` IS TRUE
When calling the following `SignatureValidator.recoverAddrImpl` function, `require(tx.origin == address(1) || tx.origin == address(6969), 'SV_SPOOF_ORIGIN')` is executed in the `mode == SignatureMode.Spoof && allowSpoofing` `else if` block. The documentation on https://github.com/code-423n4/2023-05-ambire#signaturevalidatorsol mentions that "Spoof is for spoofed signatures that only work when `tx.origin == address(1)`". Yet, the `SignatureValidator.recoverAddrImpl` function also allows spoofing if `tx.origin == address(6969)` is true. If the documentation is correct, the `SignatureValidator.recoverAddrImpl` function needs to be updated to allow spoofing only when `tx.origin == address(1)` is true. If the code is correct, the documentation needs to be updated accordingly.

https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L42-L121
```solidity
	function recoverAddrImpl(bytes32 hash, bytes memory sig, bool allowSpoofing) internal view returns (address) {
		...

		// {r}{s}{v}{mode}
		if (mode == SignatureMode.EIP712 || mode == SignatureMode.EthSign) {
			...
		} else if (mode == SignatureMode.Schnorr) {
			...
		} else if (mode == SignatureMode.Multisig) {
			...
		} else if (mode == SignatureMode.SmartWallet) {
			...
		} else if (mode == SignatureMode.Spoof && allowSpoofing) {
			// This is safe cause it's specifically intended for spoofing sigs in simulation conditions, where tx.origin can be controlled
			// We did not choose 0x00..00 because in future network upgrades tx.origin may be nerfed or there may be edge cases in which
			// it is zero, such as native account abstraction
			// slither-disable-next-line tx-origin
			require(tx.origin == address(1) || tx.origin == address(6969), 'SV_SPOOF_ORIGIN');
			require(sig.length == 33, 'SV_SPOOF_LEN');
			sig.trimToSize(32);
			// To simulate the gas usage; check is just to silence unused warning
			require(ecrecover(0, 0, 0, 0) != address(6969));
			return abi.decode(sig, (address));
		}
		...
	}
```

## [09] `SignatureValidator.recoverAddrImpl` DOES NOT CHECK FOR SIGNATURE MALLEABILITY
It is possible that malleable signatures are generated. To check for the signature malleability, please consider updating the `SignatureValidator.recoverAddrImpl` function to revert if `uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0` is true in the `mode == SignatureMode.EIP712 || mode == SignatureMode.EthSign` `if` block.

https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L42-L121
```solidity
	function recoverAddrImpl(bytes32 hash, bytes memory sig, bool allowSpoofing) internal view returns (address) {
		...

		// {r}{s}{v}{mode}
		if (mode == SignatureMode.EIP712 || mode == SignatureMode.EthSign) {
			require(sig.length == 66, 'SV_LEN');
			bytes32 r = sig.readBytes32(0);
			bytes32 s = sig.readBytes32(32);
			uint8 v = uint8(sig[64]);
			if (mode == SignatureMode.EthSign) hash = keccak256(abi.encodePacked('\x19Ethereum Signed Message:\n32', hash));
			address signer = ecrecover(hash, v, r, s);
			require(signer != address(0), 'SV_ZERO_SIG');
			return signer;
			// {sig}{verifier}{mode}
		} else if (mode == SignatureMode.Schnorr) {
			...
		} else if (mode == SignatureMode.Multisig) {
			...
		} else if (mode == SignatureMode.SmartWallet) {
			...
		} else if (mode == SignatureMode.Spoof && allowSpoofing) {
			...
		}
		...
	}
```

## [10] `SignatureValidator.splitSignature` FUNCTION DOES NOT EXECUTE `require(sig.length != 0, 'SV_SIGLEN')`
Unlike the `SignatureValidator.recoverAddrImpl` function below, the following `SignatureValidator.splitSignature` function does not execute `require(sig.length != 0, 'SV_SIGLEN')`. If `sig.length` is 0, then `sig.length - 1` will silently underflow when executing `unchecked { modeRaw = uint8(sig[sig.length - 1]) }`, which can cause `sig[sig.length - 1]` to revert without a specific reason. To improve the error handling, please consider updating the `SignatureValidator.splitSignature` function to execute `require(sig.length != 0, 'SV_SIGLEN')`.

https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L29-L36
```solidity
	function splitSignature(bytes memory sig) internal pure returns (bytes memory, uint8) {
		uint8 modeRaw;
		unchecked {
			modeRaw = uint8(sig[sig.length - 1]);
		}
		sig.trimToSize(sig.length - 1);
		return (sig, modeRaw);
	}
```

https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L42-L121
```solidity
	function recoverAddrImpl(bytes32 hash, bytes memory sig, bool allowSpoofing) internal view returns (address) {
		require(sig.length != 0, 'SV_SIGLEN');
		uint8 modeRaw;
		unchecked {
			modeRaw = uint8(sig[sig.length - 1]);
		}
		...
	}
```

## [11] `Bytes.trimToSize` FUNCTION CAN TRIM `b`'S LENGTH TO 0
Trimming `b`'s length to 0 by calling the following `Bytes.trimToSize` function does not make `b` sensible. Please consider updating the `Bytes.trimToSize` function to also revert if `newLen` equals 0.

https://github.com/AmbireTech/ambire-common/blob/368d0a636428afbad839cc41ef846ec54816cfb9/contracts/libs/Bytes.sol#L5-L10
```solidity
	function trimToSize(bytes memory b, uint256 newLen) internal pure {
		require(b.length > newLen, 'BytesLib: only shrinking');
		assembly {
			mstore(b, newLen)
		}
	}
```

## [12] MISSING REASON STRINGS IN `require` STATEMENTS
When the reason strings are missing in the `require` statements, it is unclear about why certain conditions revert. Please add descriptive reason strings for the following `require` statements.

```solidity
ambire-common\contracts\libs\SignatureValidator.sol
  75: 	require(sp != 0);
  117: 	require(ecrecover(0, 0, 0, 0) != address(6969));
```

## [13] `AmbireAccount.onERC721Received`, `AmbireAccount.onERC1155Received`, AND `AmbireAccount.onERC1155BatchReceived` FUNCTIONS CAN EMIT IMPORTANT EVENTS
For monitoring important events, the following `AmbireAccount.onERC721Received`, `AmbireAccount.onERC1155Received`, and `AmbireAccount.onERC1155BatchReceived` functions can emit events to indicate that the corresponding ERC721 or ERC1155 tokens are received.

https://github.com/AmbireTech/ambire-common/blob/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts/AmbireAccount.sol#L71-L87
```solidity
	function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
		return this.onERC721Received.selector;
	}

	function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
		return this.onERC1155Received.selector;
	}

	function onERC1155BatchReceived(
		address,
		address,
		uint256[] calldata,
		uint256[] calldata,
		bytes calldata
	) external pure returns (bytes4) {
		return this.onERC1155BatchReceived.selector;
	}
```

## [14] `require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL')` CAN BE REFACTORED INTO A MODIFIER TO BE USED IN RESPECTIVE FUNCTIONS
`require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL')` are executed in the respective functions. For better code organization and maintainability, please consider refactoring `require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL')` into a modifier to be used in these functions.

```solidity
ambire-common\contracts\AmbireAccount.sol
  113: 	require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL');
  120: 	require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL');
  127: 	require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL');
  212: 	require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL');
```

## [15] REDUNDANT RETURN STATEMENT FOR `readBytes32` FUNCTION, WHICH HAS NAMED RETURN, CAN BE REMOVED
When a function has a named return and a return statement, this return statement becomes redundant. To improve readability and maintainability, the return statement for the following `readBytes32` function can be removed.

https://github.com/AmbireTech/ambire-common/blob/368d0a636428afbad839cc41ef846ec54816cfb9/contracts/libs/Bytes.sol#L22-L33
```solidity
	function readBytes32(bytes memory b, uint256 index) internal pure returns (bytes32 result) {
		// Arrays are prefixed by a 256 bit length parameter
		index += 32;

		require(b.length >= index, 'BytesLib: length');

		// Read the bytes32 from array memory
		assembly {
			result := mload(add(b, index))
		}
		return result;
	}
```

## [16] `uint256` CAN BE USED INSTEAD OF `uint`
Both `uint` and `uint256` are used in the `AmbireAccount` contract. In favor of explicitness, please consider using `uint256` instead of `uint` in the following code.

```solidity
ambire-common\contracts\AmbireAccount.sol
  15: 	mapping(bytes32 => uint) public scheduledRecoveries;
  62: 	privileges[addrs[i]] = bytes32(uint(1));
  63: 	emit LogPrivilegeChanged(addrs[i], bytes32(uint(1)));
  94: 	address fallbackHandler = address(uint160(uint(privileges[FALLBACK_HANDLER_SLOT])));
```

## [17] WORD TYPING TYPO
`contracft` can be updated to `contract` in the following code comment.

https://github.com/AmbireTech/ambire-common/blob/8cca47a6f98ea364c3838c1727ff956a00aaa6d2/contracts/AmbireAccountFactory.sol#L15
```solidity
	// @notice allows anyone to deploy any contracft with a specific code/salt
```

## [18] `AmbireAccount.executeMultiple` FUNCTION CAN HAVE CODE ON A SEPARATE LINE
To make the code more readable, please consider coding `execute(toExec[i].txns, toExec[i].signature)` on a separate line in the following `AmbireAccount.executeMultiple` function.

https://github.com/AmbireTech/ambire-common/blob/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts/AmbireAccount.sol#L197-L199
```solidity
	function executeMultiple(ExecuteArgs[] calldata toExec) external payable {
		for (uint256 i = 0; i != toExec.length; i++) execute(toExec[i].txns, toExec[i].signature);
	}
```

## [19] INCOMPLETE NATSPEC COMMENTS
NatSpec comments provide rich code documentation. The following functions miss the `@param` and/or `@return` comments. Please consider completing the NatSpec comments for these functions.

```solidity
ambire-common\contracts\AmbireAccount.sol
  112: 	function setAddrPrivilege(address addr, bytes32 priv) external payable {	
  119: 	function tryCatch(address to, uint256 value, bytes calldata data) external payable {	
  126: 	function tryCatchLimit(address to, uint256 value, bytes calldata data, uint256 gasLimit) external payable {	
  135: 	function execute(Transaction[] calldata txns, bytes calldata signature) public payable {	
  196: 	function executeMultiple(ExecuteArgs[] calldata toExec) external payable {	
  202: 	function executeBySender(Transaction[] calldata txns) external payable {
  211: 	function executeBySelf(Transaction[] calldata txns) external payable {	
  240: 	function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {	
  251: 	function supportsInterface(bytes4 interfaceID) external pure returns (bool) {

ambire-common\contracts\AmbireAccountFactory.sol
  17: 	function deploy(bytes calldata code, uint256 salt) external {	
  24: 	function deployAndExecute(	
  35: 	function call(address to, uint256 value, bytes calldata data, uint256 gas) external {	
  44: 	function deploySafe(bytes memory code, uint256 salt) internal returns (address) {
```

## [20] MISSING NATSPEC COMMENTS
NatSpec comments provide rich code documentation. The following functions miss NatSpec comments. Please consider adding NatSpec comments for these functions.

```solidity
ambire-common\contracts\AmbireAccount.sol
  71: 	function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {	
  75: 	function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {	
  79: 	function onERC1155BatchReceived(	
  216: 	function executeBatch(Transaction[] memory txns) internal {	
  225: 	function executeCall(address to, uint256 value, bytes memory data) internal {	

ambire-common\contracts\libs\Bytes.sol
  5: 	function trimToSize(bytes memory b, uint256 newLen) internal pure {	

ambire-common\contracts\libs\SignatureValidator.sol
  29: 	function splitSignature(bytes memory sig) internal pure returns (bytes memory, uint8) {	
  38: 	function recoverAddr(bytes32 hash, bytes memory sig) internal view returns (address) {	
  42: 	function recoverAddrImpl(bytes32 hash, bytes memory sig, bool allowSpoofing) internal view returns (address) {	
```