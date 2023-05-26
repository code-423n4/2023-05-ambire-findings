## `AmbireAccountFactory.deploySafe()` does not guarantee that no call hasn't already been made on the deployed contract
When [deploying and executing](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L24) it is possible that another of the privileged signers might have made a call on the already deployed contract, changing its state. While this can only be one of the designated signers with privilege as set by the deployer, it may be against the wishes of the deployer that someone else makes a first function call.
Consider allowing only a single address with privilege in the constructor such that the deployer would be the only one who could make a first call.

## Fallback handler should not be allowed to be `this`
In AmbireAccount.sol, if `address(uint160(uint(privileges[FALLBACK_HANDLER_SLOT]))) == address(this)` anyone could call the functions protected by `require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL');`, with obvious disastrous consequences. This seems like an unnecessary attack surface to expose. Consider checking that this is not the case, either when setting the privileges (in `setAddrPrivilege()`) or in the fallback itself.

## Schnorr signature validation may be incompatible with the intended signers
The Schnorr signature scheme implemented for validation [in `SignatureValidator.recoverAddrImpl()`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L63-L82) is engineered to leverage Ethereums `ecrecover` for its calculations. It also uses a specific hash function (keccak256 of a certain encoding of data). As far as I can tell this is not a standard Schnorr scheme. It is important to note that both signer and validator must agree on the same group and hash function. The implemented Schnorr validation will not work with any other Schnorr scheme.
Consider whether AmbireAccount is expected to interface with other Schnorr scheme implementations and if so make sure that the same Schnorr scheme is used.

## Schnorr signature length is not checked
When [`SignatureValidator.recoverAddrImpl()` is called with a Schnorr signature](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L63) it is not checked that it has the correct length, unlike for `SignatureMode.EIP712` and `SignatureMode.EthSign`.
Consider checking that `sig`, before trimming, has a length of `129` (`(bytes32, bytes32, bytes32, uint8)` plus the `modeRaw` byte).

## `LogPrivilegeChanged` does not adequately describe the change
`LogPrivilegeChanged(addr, priv)` [is emitted when the privilege of `addr` is changed to `priv`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L115) (also in the constructor but there it is first set, rather than changed). Since the previous value is not emitted it is difficult to know whether and how it was meaningfully changed, especially considering that privileges are `bytes32` but generally carry their meaning only in being non-zero, but may also encode for recovery and the fallback handler.
Consider including the previous privilege in the event, and perhaps emit a different event when the fallback handler is changed and when recovery info hash is set (this would then probably involve creating a separate function for setting this).

## Consider indexing unindexed events
Instances:
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L7

## Error message with opposite meaning
The anti-bricking checks return `PRIVILEGE_NOT_DOWNGRADED` if the sender/signer key removes their own privilege. If this is attempted this error message suggests that the privilege should have been downgraded but wasn't, which is the opposite of what is intended. The error message should therefore rather be `PRIVILEGE_DOWNGRADED` or `PRIVILEGE_MUST_NOT_BE_DOWNGRADED` or similar.
Instances:
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L193
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L207

## Non-scheduled recoveries can be cancelled
When a recovery is cancelled [`LogRecoveryCancelled` is emitted](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L173). But this happens even if the recovery wasn't previously scheduled, giving the false impression that it was.
Consider reverting attempts to cancel a recovery which hasn't already been scheduled.

## `AmbireAccount.constructor()` does not allow for custom privileges
`AmbireAccount.constructor()` only sets [`privileges[addrs[i]] = bytes32(uint(1));`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L62). A second call is therefore necessary to set the remaining `privileges`, at `FALLBACK_HANDLER_SLOT` and the value `recoveryInfoHash`.
Consider adding a parameter with the values to set at `addrs`.

## It makes more sense to check `signatures.length > 0` than `signer != address(0)` for multisigs
In `SignatureValidator.recoverAddrImpl()` for `SignatureMode.Multisig` it is [checked that last `signer != address(0)`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L92) after validating each signature in the array `signatures`. This can be `address(0)` only if `signatures.length == 0`, in which case the for-loop is skipped, leaving `signer` unassigned. It would therefore make more sense to instead check `require(signatures.length != 0, 'SV_ZERO_SIG');`, just after L85.

## Redundant require/revert
In `SignatureValidator.recoverAddrImpl()` it is first checked that [`require(modeRaw < uint8(SignatureMode.LastUnused), 'SV_SIGMODE');`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L49). This ensures that `SignatureMode mode = SignatureMode(modeRaw);` will be one of the available signature modes. Each of these modes are then considered and the function returns in each case. But at the end of the function there is a [`revert('SV_TYPE');`](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/libs/SignatureValidator.sol#L120). This line can therefore not be reached.
Consider removing either of these checks, as they have the same effect.

## Group order denoted `Q` may be confused with the public key
In SignatureValidator.sol the Schnorr signature scheme group order is denoted `Q`. While in the context of Schnorr signatures a lowercase 'q' is sometimes used to denote the group order, this particular Schnorr signature scheme uses the subgroup generated by the secp256k1 base point, the order of which is usually denoted `n`. I.e. the value which is here denoted `Q` is usually known as `n`. Furthermore, secp256k1 is primarily thought of in the context of ECDSA, where `Q` usually denotes the public key.
Consider renaming `Q` to `n`.

## Use `uint256` instead of `uint`
Consider using the explicit `uint256` consistently instead of its alias `uint`.
Instances:
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L15
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L62
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L63
https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L94

## Typos
[contracft -> contract](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccountFactory.sol#L15)
[// bytes4(keccak256("isValidSignature(bytes32,bytes)") -> // bytes4(keccak256("isValidSignature(bytes32,bytes)"))](https://github.com/AmbireTech/ambire-common/blob/5c54f8005e90ad481df8e34e85718f3d2bfa2ace/contracts/AmbireAccount.sol#L243)
