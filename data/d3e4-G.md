

## `splitSignature()` may be redundant
`SignatureValidator.splitSignature()` seems to only ever be used once, in [AmbireAccount.sol#L145](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L145), where only its first return value is used, which is `signature` with its last byte removed. We can thus simply inline `Bytes.trimToSize()` instead:
```diff
+ import './Bytes.sol';
...
- (bytes memory sig, ) = SignatureValidator.splitSignature(signature);
+ bytes memory sig = Bytes.trimToSize(signature, signature.length - 1);
```

## Cache variable
`sig.length - 1` may be cached in memory in
```solidity
unchecked {
    modeRaw = uint8(sig[sig.length - 1]);
}
sig.trimToSize(sig.length - 1);
```
## Unnecessary require in `AmbireAccountFactory.deploySafe()`
`AmbireAccountFactory.deploySafe(code, salt)` returns the address where the bytecode `code` is deployed, itself deploying it first if it isn't already deployed. It is therefore meaningless to check that the fresh deployment is successful, which only amounts to checking that the opcode CREATE2 works as expected. Specifically:
`require(addr == expectedAddr, 'FAILED_MATCH');` in `AmbireAccountFactory.deploySafe()` can be removed as it must be assumed that the calculation of `expectedAddr` is correct.
`require(addr != address(0), 'FAILED_DEPLOYING');` will never trigger as CREATE2 only returns `address(0)` when trying to deploy to the same address twice, which is not the case since it is already checked that `extcodesize(addr) == 0`.

## Unnecessary require in `SignatureValidator.recoverAddrImpl()`
`address signer = address(wallet);` so `require(signer != address(0), 'SV_ZERO_SIG');` is redundant in `SignatureValidator.recoverAddrImpl()`, as it would already have reverted in `wallet.isValidSignature(hash, sig)` because of a function call to the zero address.

## Unnecessary declaration of `currentNonce``
In `AmbireAccount.execute()` `currentNonce` is declared: [`uint256 currentNonce = nonce;`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L136), but never changed, and then used to update `nonce`: [`nonce = currentNonce + 1;`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L189). `nonce` alone can be used throughout and then incremented by `nonce++`.

## It is more gas efficient to revert with a custom error than a require with a string
Instances:
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L113
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L120
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L127
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L153
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L157
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L170
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L182
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L193
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L204
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L207
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L213

https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L36
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L38
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L59
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L60

https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/Bytes.sol#L6
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/Bytes.sol#L26

https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L43
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L49
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L54
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L60
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L75
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L81
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L82
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L92
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L96
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L103
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L105
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L113
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L114
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L117

## Constructors may be declared `payable` to save gas
Instances:
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L58
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L11

