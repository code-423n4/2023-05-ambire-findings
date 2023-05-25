Low:
L-01:recoveryInfoHash Setting up security issues
Currently, the recovery information is set by passing `bytes32` through `setAddrPrivilege()`.
There is no way to check if this is a legal `RecoveryInfo` format, and if the user sets the wrong `bytes32` by mistake, it will not be possible to `recover` when recovery is needed.
Since this calculation is very important, it is recommended to add format verification
such as:
add setRecovery
```solidity
+    function setRecovery(address addr, RecoveryInfo info) external payable {
+        require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL');
+        require(info.keys.length > 0,"bad info");
+        require(info.timelock > 0,"bad info");]
+        //....other check keys.address !=0        
+        bytes32 priv = abi.encode(info);
+        privileges[addr] = priv;
+        emit LogPrivilegeChanged(addr, priv);
+    }
```


L-02:execute() Security risks of missing deadLine restrictions

Currently only `nonce` is used to prevent replay
But if a transaction `revert` fails, the transaction signature is exposed, and the user finds that there is no need to execute it, so it is not retried
and no other transaction is executed afterward
Since there is no time limit on the signature, it may be a long time before a malicious user can replay the transaction again using the signature of the last failed transaction (assuming that the user did not execute any transaction `nonce` during the period and did not change)

So it is recommended to add the deadLine mechanism to avoid the failed transaction, after a long time the user did not expect when the malicious replay

```solidity

-   function execute(Transaction[] calldata txns, bytes calldata signature) public payable {
+   function execute(Transaction[] calldata txns, uint256 deadLine, bytes calldata signature) public payable {

    require(block.timestamp>=deadLine,"bad deadLine");

-   bytes32 hash = keccak256(abi.encode(address(this), block.chainid, currentNonce, txns));   
+   bytes32 hash = keccak256(abi.encode(address(this), block.chainid, currentNonce, txns , deadLine));  
```

L-03: supportsInterface() Lack of support ERC721TokenReceiver.interfaceId

```solidity
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {       
        return
+           interfaceId == type(ERC721TokenReceiver).interfaceId ||        
            interfaceID == 0x01ffc9a7 || // ERC-165 support (i.e. `bytes4(keccak256('supportsInterface(bytes4)'))`).
            interfaceID == 0x4e2312e0; // ERC-1155 `ERC1155TokenReceiver` support (i.e. `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")) ^ bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`).
    }
```

L-04:deployAndExecute() missing `payable`

It is recommended to add `payable` to execute requests that require passing `eth` to AmbireAccount

```solidity
    function deployAndExecute(
        bytes calldata code,
        uint256 salt,
        AmbireAccount.Transaction[] calldata txns,
        bytes calldata signature
-   ) external {
+   ) external payable{
        address payable addr = payable(deploySafe(code, salt));
-       AmbireAccount(addr).execute(txns, signature);        
+       AmbireAccount(addr).execute{value:msg.value}(txns, signature);
    }
```