# EIP3009Forwarder

A Solidity implementation of EIP-3009 for gas-less ERC-20 token transfers using EIP-712 signatures.

## Overview

The EIP3009Forwarder contract enables meta-transactions for ERC-20 tokens, allowing users to authorize token transfers via cryptographic signatures without paying gas fees themselves. A third party (relayer) can submit these pre-signed authorizations and pay the gas costs.

## Features

- **Gas-less transfers**: Users sign authorizations off-chain, relayers submit on-chain
- **EIP-712 compliant**: Uses structured data signing for security
- **Replay protection**: Unique nonces prevent transaction replays
- **Time-bounded authorizations**: Support for `validAfter` and `validBefore` timestamps
- **Authorization cancellation**: Users can invalidate unused authorizations
- **Two transfer modes**:
  - `transferWithAuthorization`: Any relayer can submit
  - `receiveWithAuthorization`: Only the recipient can submit
- **USDC-style signature bytes**: `bytes signature` variants support EOA (r,s,v) and contract wallets (ERC-1271)

## Installation

This project uses [Foundry](https://book.getfoundry.sh/). Install dependencies:

```shell
forge install
```

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Format

```shell
forge fmt
```

### Gas Snapshots

```shell
forge snapshot
```

### Deploy

1. Create a deployment script in `script/`
2. Deploy using private key:

```shell
forge script script/DeployForwarder.s.sol:DeployForwarder \
  --rpc-url <your_rpc_url> \
  --private-key <your_private_key> \
  --broadcast \
  --sig "run(address,string)" \
  <erc20_token_address> \
  "<version>"
```

3. Deploy using environment account:

```shell
forge script script/DeployForwarder.s.sol:DeployForwarder \
  --rpc-url <your_rpc_url> \
  --account <your_account_name> \
  --broadcast \
  --sig "run(address,string)" \
  <erc20_token_address> \
  "<version>"
```

4. Deploy using environment account on SKALE:

```shell
forge script script/DeployForwarder.s.sol:DeployForwarder \
  --rpc-url <your_rpc_url> \
  --account <your_account_name> \
  --broadcast \
  --legacy \
  --sig "run(address,string)" \
  <erc20_token_address> \
  "<version>"
```

## Contract Interface

### Core Functions

#### `transferWithAuthorization`
Executes a token transfer using a signed authorization. Can be called by any relayer.

```solidity
function transferWithAuthorization(
    address from,
    address to,
    uint256 value,
    uint256 validAfter,
    uint256 validBefore,
    bytes32 nonce,
    bytes calldata signature
) external;

function transferWithAuthorization(
    address from,
    address to,
    uint256 value,
    uint256 validAfter,
    uint256 validBefore,
    bytes32 nonce,
    uint8 v,
    bytes32 r,
    bytes32 s
) external;
```

#### `receiveWithAuthorization`
Executes a token transfer where the recipient must be the transaction submitter.

```solidity
function receiveWithAuthorization(
    address from,
    address to,
    uint256 value,
    uint256 validAfter,
    uint256 validBefore,
    bytes32 nonce,
    bytes calldata signature
) external;

function receiveWithAuthorization(
    address from,
    address to,
    uint256 value,
    uint256 validAfter,
    uint256 validBefore,
    bytes32 nonce,
    uint8 v,
    bytes32 r,
    bytes32 s
) external;
```

#### `cancelAuthorization`
Cancels an unused authorization to prevent future execution.

```solidity
function cancelAuthorization(
    address authorizer,
    bytes32 nonce,
    bytes calldata signature
) external;

function cancelAuthorization(
    address authorizer,
    bytes32 nonce,
    uint8 v,
    bytes32 r,
    bytes32 s
) external;
```

### View Functions

- `authorizationState(address, bytes32)`: Check if a nonce has been used
- `DOMAIN_SEPARATOR()`: Get the EIP-712 domain separator
- `underlyingToken()`: Get the wrapped token address
- `hasApproval(address, uint256)`: Check if sufficient allowance exists
- `getAllowance(address)`: Get current allowance amount

## EIP-712 Type Hashes

The contract uses the following EIP-712 structured data types:

```solidity
// TransferWithAuthorization
keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")

// ReceiveWithAuthorization  
keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")

// CancelAuthorization
keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
```

## Usage Example

```solidity
// 1. Deploy forwarder for a token
EIP3009Forwarder forwarder = new EIP3009Forwarder(
    tokenAddress,
    "MyForwarder",
    "1"
);

// 2. User approves forwarder to spend tokens
IERC20(tokenAddress).approve(address(forwarder), amount);

// 3. User signs authorization off-chain (using web3, ethers.js, etc.)
// 4. Relayer submits the signed authorization
forwarder.transferWithAuthorization(
    from,
    to,
    value,
    validAfter,
    validBefore,
    nonce,
    signature // EOA signatures are packed as r || s || v
);
```

## Security Considerations

- **Token Approval Required**: Users must approve the forwarder contract before authorizations can be executed
- **Nonce Management**: Use unique, unpredictable nonces to prevent replay attacks
- **Time Bounds**: Set appropriate `validAfter` and `validBefore` timestamps
- **Signature Validation**: All signatures are validated against EIP-712 structured data
- **Reentrancy Protection**: Contract includes reentrancy guards on state-changing functions

## Development

### Running Tests

```shell
# Run all tests
forge test

# Run tests with verbosity
forge test -vvv

# Run specific test
forge test --match-test test_succeeds_transferWithAuthorization
```

### Local Development

Start a local Ethereum node:

```shell
anvil
```

## Foundry Documentation

For more information on Foundry:
- **Forge**: Ethereum testing framework
- **Cast**: CLI for interacting with contracts  
- **Anvil**: Local Ethereum node
- **Chisel**: Solidity REPL

Visit [Foundry Book](https://book.getfoundry.sh/) for complete documentation.

## License

See MIT License in [License](./LICENSE)

## Security

This software is provided for educational and experimental purposes. Smart contracts involve significant risk and this code has not undergone professional security auditing.

**BY USING THIS SOFTWARE, YOU ACKNOWLEDGE AND AGREE THAT:**

1. **No Warranty**: This software is provided "as is" without any warranties or guarantees of any kind.

2. **Use at Your Own Risk**: You use this software entirely at your own risk. The authors and contributors are not responsible for any losses, damages, or security vulnerabilities.

3. **Not Financial Advice**: This software does not constitute financial, investment, or legal advice.

4. **Security Auditing Required**: Before using in production, you must conduct thorough security audits by qualified professionals.

5. **Regulatory Compliance**: You are solely responsible for ensuring compliance with applicable laws and regulations in your jurisdiction.

6. **No Liability**: The authors, contributors, and associated parties shall not be liable for any direct, indirect, incidental, special, consequential, or exemplary damages arising from the use of this software.

**ALWAYS CONDUCT THOROUGH TESTING AND SECURITY AUDITS BEFORE DEPLOYING TO MAINNET OR HANDLING REAL VALUE.**
