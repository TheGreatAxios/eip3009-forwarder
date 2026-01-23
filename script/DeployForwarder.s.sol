// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {EIP3009Forwarder} from "../src/EIP3009Forwarder.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {console} from "forge-std/console.sol";

/**
 * @title DeployForwarder
 * @notice A Foundry script to deploy the EIP3009Forwarder contract.
 * @dev This script automatically determines the EIP-712 domain name by fetching the
 *      symbol from the target ERC20 token and appending " Forwarder".
 *
 *      To run this script, use the following command:
 *      forge script script/DeployForwarder.s.sol:DeployForwarder --rpc-url <your_rpc_url> \
 *      --private-key <your_private_key> --broadcast -- \
 *      <erc20_token_address> "<version>"
 */
contract DeployForwarder is Script {
    /**
     * @notice The main entry point for the deployment script.
     * @param _tokenAddress The address of the ERC20 token to be forwarded.
     * @param _version The version for the EIP-712 domain (e.g., "1").
     * @return The newly deployed EIP3009Forwarder contract instance.
     */
    function run(address _tokenAddress, string memory _version) external returns (EIP3009Forwarder) {
        // --- Input Validation ---
        require(_tokenAddress != address(0), "Token address cannot be the zero address.");

        // --- Automatically Generate the EIP-712 Name ---
        // Create an interface to the on-chain token contract
        IERC20Metadata token = IERC20Metadata(_tokenAddress);
        // Fetch the token's symbol
        string memory tokenSymbol = token.symbol();
        // Concatenate the symbol with " Forwarder" to create the name
        string memory forwarderName = string(abi.encodePacked(tokenSymbol, " Forwarder")); // <--- DYNAMIC NAME

        console.log("Deploying forwarder for token:", tokenSymbol);
        console.log("EIP-712 Domain Name:", forwarderName);

        // --- Begin Deployment Transaction ---
        vm.startBroadcast();

        // --- Deploy the Contract with the generated name ---
        EIP3009Forwarder forwarder = new EIP3009Forwarder(
            _tokenAddress,
            forwarderName, // <--- USE DYNAMIC NAME
            _version
        );

        // --- Stop Broadcasting ---
        vm.stopBroadcast();

        console.log("EIP3009Forwarder deployed at:", address(forwarder));
        console.log("Underlying Token:", forwarder.underlyingToken());

        return forwarder;
    }
}
