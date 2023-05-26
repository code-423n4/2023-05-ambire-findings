# `AmbireAccountFactory::deploy` only allows deploying contract which does not require ETH during its deployment.
Current implementation of `deploy` only allows to deploy smart contract which does not require ETH during their deployment, contradicting the comment `@notice allows anyone to deploy any contracft with a specific code/salt`

This happens because, when a contract is created, a payment of 0 ether is enforced

```solidity
// In deploySafe, which is called by deploy
assembly {
    addr := create2(
        0, // payment in eth
        add(code, 0x20),
        mload(code),
        salt)
}
```

The comment or the code should be modified in order to be congruent

# `AmbireAccountFactory::deploySafe` can be refactor in order to save gas
Current `AmbireAccountFactory::deploySafe` can be summarized in next pseudocode:
1. Get expected deployment address
2. If it was not deployed yet, deploy it with `create2` and emit log
3. Return the expected deployment address

However, `create2` has only two possible outputs:
* `address(0)` is the deployment has failed given that the contract was already deployed
* Address different to `address(0)` if the contract was successfully deployed

`create2` can also revert for many reasons, for instance if the transaction run out of gas.

Therefore there is no need to check the size of the address where the code is going to be deployed.

Therefore the function can be redefine as 
```solidity
	function deploySafe(bytes memory code, uint256 salt) internal returns (address) {
        address addr;
		assembly {
			addr := create2(0, add(code, 0x20), mload(code), salt)
		}
        if (addr == address(0)){
            // Already deployed address case
            return address(
			uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(code)))))
		    );
        }
        // If the contract was not deployed yet emit event and return new address
        emit LogDeployed(addr, salt);
        return addr;
	}
```