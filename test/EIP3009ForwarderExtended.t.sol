// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EIP3009ForwarderExtended} from "../src/EIP3009ForwarderExtended.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @notice A mock ERC20 token for testing purposes.
 */
contract MockERC20 is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    string public name = "Mock Token";
    string public symbol = "MTKN";
    uint8 public decimals = 18;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/**
 * @notice Mock ERC-1271 wallet for testing smart contract signatures.
 * @dev Implements ERC-1271 with configurable behavior for testing.
 */
contract MockERC1271Wallet is IERC1271 {
    // Toggle for testing valid/invalid signatures
    bool public shouldReturnValid = true;

    // Gas to consume during validation (for testing gas limits)
    uint256 public gasToConsume = 0;

    bytes4 private constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /**
     * @notice Set whether the wallet should return valid or invalid signatures.
     * @param _shouldReturnValid True to return valid, false for invalid.
     */
    function setShouldReturnValid(bool _shouldReturnValid) external {
        shouldReturnValid = _shouldReturnValid;
    }

    /**
     * @notice Set gas to consume during signature validation.
     * @param _gasToConsume Amount of gas to consume.
     */
    function setGasToConsume(uint256 _gasToConsume) external {
        gasToConsume = _gasToConsume;
    }

    /**
     * @notice ERC-1271 signature validation.
     * @param _hash The hash that was signed.
     * @param _signature The signature bytes (unused in mock).
     * @return magicValue The magic value if signature is valid.
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view returns (bytes4 magicValue) {
        // Consume gas if specified (for testing gas limit enforcement)
        if (gasToConsume > 0) {
            uint256 gasStart = gasleft();
            while (gasStart - gasleft() < gasToConsume) {
                // Burn gas
            }
        }

        if (shouldReturnValid) {
            return ERC1271_MAGIC_VALUE;
        } else {
            return 0xffffffff; // Invalid magic value
        }
    }

    // Allow the wallet to receive tokens
    receive() external payable {}
}

/**
 * @title Test suite for EIP3009ForwarderExtended contract
 */
contract EIP3009ForwarderExtendedTest is Test {
    // Contracts
    EIP3009ForwarderExtended public forwarder;
    MockERC20 public token;
    MockERC1271Wallet public smartWallet;

    // Users
    address alice;
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");
    address relayer = makeAddr("relayer");
    uint256 alicePrivateKey = 0xA11CE;

    // EIP-712 Constants
    bytes32 constant TRANSFER_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 constant RECEIVE_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 constant CANCEL_TYPEHASH = keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    bytes32 DOMAIN_SEPARATOR;

    // Test constants
    uint256 constant INITIAL_MINT_AMOUNT = 1_000_000 * 1e18;
    uint256 constant TRANSFER_AMOUNT = 100 * 1e18;

    /**
     * @notice Set up the test environment before each test case.
     */
    function setUp() public {
        // 1. Derive Alice's address from the private key
        alice = vm.addr(alicePrivateKey);

        // 2. Deploy the mock token
        token = new MockERC20();

        // 3. Deploy a smart wallet for testing ERC-1271
        smartWallet = new MockERC1271Wallet();

        // 4. Deploy the forwarder
        forwarder = new EIP3009ForwarderExtended(address(token), "TestForwarder", "1");

        // 5. Get the domain separator
        DOMAIN_SEPARATOR = forwarder.DOMAIN_SEPARATOR();

        // 6. Fund Alice's account (EOA)
        token.mint(alice, INITIAL_MINT_AMOUNT);

        // 7. Fund smart wallet
        token.mint(address(smartWallet), INITIAL_MINT_AMOUNT);

        // 8. Alice approves the forwarder to spend her tokens
        vm.prank(alice);
        token.approve(address(forwarder), type(uint256).max);

        // 9. Smart wallet approves the forwarder
        vm.prank(address(smartWallet));
        token.approve(address(forwarder), type(uint256).max);

        // Label addresses for easier debugging
        vm.label(alice, "Alice");
        vm.label(bob, "Bob");
        vm.label(charlie, "Charlie");
        vm.label(relayer, "Relayer");
        vm.label(address(token), "MockToken");
        vm.label(address(forwarder), "ExtendedForwarder");
        vm.label(address(smartWallet), "SmartWallet");
    }

    // =============================================================
    //                      Helper Functions
    // =============================================================

    /**
     * @notice Signs a TransferWithAuthorization message.
     */
    function _signTransfer(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Signs a ReceiveWithAuthorization message.
     */
    function _signReceive(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(RECEIVE_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Signs a CancelAuthorization message.
     */
    function _signCancel(address authorizer, bytes32 nonce, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(CANCEL_TYPEHASH, authorizer, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Creates a dummy signature for ERC-1271 testing.
     */
    function _createDummySignature() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
    }

    // =============================================================
    //                      Admin Functions
    // =============================================================

    /**
     * @notice Verify two-step admin transfer works.
     */
    function testAdminTransfer_TwoStepProcess() public {
        // Arrange
        address newAdmin = charlie;
        address currentAdmin = forwarder.getAdmin();

        // Act 1: Initiate transfer
        vm.prank(currentAdmin);
        forwarder.transferAdmin(newAdmin);

        // Assert 1: Check pending admin
        assertEq(forwarder.getAdmin(), currentAdmin, "Admin should not change immediately");

        // Act 2: Accept transfer
        vm.prank(newAdmin);
        forwarder.acceptAdmin();

        // Assert 2: Admin changed
        assertEq(forwarder.getAdmin(), newAdmin, "Admin should be updated");
    }

    /**
     * @notice Verify only pending admin can accept.
     */
    function testOnlyPendingAdminCanAccept() public {
        // Arrange
        address currentAdmin = forwarder.getAdmin();
        vm.prank(currentAdmin);
        forwarder.transferAdmin(charlie);

        // Act & Assert: Non-pending admin tries to accept
        vm.expectRevert(EIP3009ForwarderExtended.NotAdmin.selector);
        vm.prank(bob);
        forwarder.acceptAdmin();
    }

    /**
     * @notice Verify admin can cancel pending transfer.
     */
    function testRenounceAdminTransfer() public {
        // Arrange
        address currentAdmin = forwarder.getAdmin();
        vm.prank(currentAdmin);
        forwarder.transferAdmin(charlie);

        // Act: Cancel the transfer
        vm.prank(currentAdmin);
        forwarder.renounceAdminTransfer();

        // Assert: Pending admin should be cleared
        vm.expectRevert(EIP3009ForwarderExtended.NotAdmin.selector);
        vm.prank(charlie);
        forwarder.acceptAdmin();
    }

    // =============================================================
    //                   Gas Limit Functions
    // =============================================================

    /**
     * @notice Admin can set reasonable gas limit.
     */
    function testSetGasLimit_ValidRange() public {
        // Arrange
        address admin = forwarder.getAdmin();
        uint256 newGasLimit = 30000;

        // Act
        vm.prank(admin);
        forwarder.setERC1271GasLimit(newGasLimit);

        // Assert: Function should not revert
    }

    /**
     * @notice Zero gas limit rejected.
     */
    function testSetGasLimit_ZeroReverts() public {
        // Arrange
        address admin = forwarder.getAdmin();

        // Act & Assert
        vm.expectRevert();
        vm.prank(admin);
        forwarder.setERC1271GasLimit(0);
    }

    /**
     * @notice Gas limit > 50000 rejected (50k cap).
     */
    function testSetGasLimit_ExceedsMaximum() public {
        // Arrange
        address admin = forwarder.getAdmin();

        // Act & Assert: 50k cap enforced
        vm.expectRevert(EIP3009ForwarderExtended.InvalidGasLimit.selector);
        vm.prank(admin);
        forwarder.setERC1271GasLimit(50001);
    }

    // =============================================================
    //                 ERC-1271 Validation
    // =============================================================

    /**
     * @notice Successful ERC-1271 transfer.
     */
    function testTransferWith_ERC1271Signature() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");
        bytes memory signature = _createDummySignature();

        // Act: Smart wallet transfers tokens
        forwarder.transferWithAuthorization(
            address(smartWallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature
        );

        // Assert
        assertEq(
            token.balanceOf(address(smartWallet)),
            INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT,
            "Smart wallet balance should decrease"
        );
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT, "Bob should receive tokens");
        assertTrue(forwarder.authorizationState(address(smartWallet), nonce), "Nonce should be marked as used");
    }

    /**
     * @notice Successful ERC-1271 receive.
     */
    function testReceiveWith_ERC1271Signature() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce2");
        bytes memory signature = _createDummySignature();

        // Act: Bob calls receiveWithAuthorization
        vm.prank(bob);
        forwarder.receiveWithAuthorization(
            address(smartWallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature
        );

        // Assert
        assertEq(
            token.balanceOf(address(smartWallet)),
            INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT,
            "Smart wallet balance should decrease"
        );
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT, "Bob should receive tokens");
    }

    /**
     * @notice Successful ERC-1271 cancel.
     */
    function testCancelWith_ERC1271Signature() public {
        // Arrange
        bytes32 nonceToCancel = keccak256("nonce-to-cancel");
        bytes memory signature = _createDummySignature();

        // Act: Cancel authorization
        forwarder.cancelAuthorization(address(smartWallet), nonceToCancel, signature);

        // Assert: Nonce is used
        assertTrue(forwarder.authorizationState(address(smartWallet), nonceToCancel), "Nonce should be marked as used");
    }

    /**
     * @notice Invalid signature from wallet rejected.
     */
    function testERC1271_InvalidSignatureFails() public {
        // Arrange
        smartWallet.setShouldReturnValid(false);
        bytes32 nonce = keccak256("invalid-nonce");
        bytes memory signature = _createDummySignature();

        // Act & Assert: Invalid signature should fail
        vm.expectRevert(EIP3009ForwarderExtended.ERC1271ValidationFailed.selector);
        forwarder.transferWithAuthorization(
            address(smartWallet), bob, TRANSFER_AMOUNT, 0, block.timestamp + 1 hours, nonce, signature
        );
    }

    // =============================================================
    //                   EOA Path Tests
    // =============================================================

    /**
     * @notice EOA signature works in extended contract.
     */
    function testTransferWith_EOASignature() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("eoa-nonce");

        bytes memory signature =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);

        // Act: Relayer submits the transaction
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature);

        // Assert
        assertEq(token.balanceOf(alice), INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT, "Alice's balance should decrease");
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT, "Bob should receive tokens");
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be marked as used");
    }

    /**
     * @notice EOA receive works.
     */
    function testReceiveWith_EOASignature() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("eoa-receive-nonce");

        bytes memory signature =
            _signReceive(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);

        // Act: Bob submits the transaction
        vm.prank(bob);
        forwarder.receiveWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature);

        // Assert
        assertEq(token.balanceOf(alice), INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT, "Alice's balance should decrease");
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT, "Bob should receive tokens");
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be marked as used");
    }
}
