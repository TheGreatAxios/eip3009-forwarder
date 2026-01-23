// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EIP3009Forwarder} from "../src/EIP3009Forwarder.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
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
 * @notice A mock ERC-1271 contract wallet for testing purposes.
 */
contract MockERC1271Wallet is IERC1271 {
    using ECDSA for bytes32;

    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function approveToken(IERC20 token, address spender, uint256 amount) external {
        token.approve(spender, amount);
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

/**
 * @notice A mock ERC-1271 wallet that burns gas during validation.
 */
contract MockERC1271WalletGasGuzzler is IERC1271 {
    using ECDSA for bytes32;

    address public immutable owner;
    uint256 public gasToConsume;

    constructor(address _owner) {
        owner = _owner;
    }

    function setGasToConsume(uint256 _gasToConsume) external {
        gasToConsume = _gasToConsume;
    }

    function approveToken(IERC20 token, address spender, uint256 amount) external {
        token.approve(spender, amount);
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        uint256 gasStart = gasleft();
        while (gasStart - gasleft() < gasToConsume) {}

        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

/**
 * @title Test suite for EIP3009Forwarder contract
 */
contract EIP3009ForwarderTest is Test {
    // Contracts
    EIP3009Forwarder public forwarder;
    MockERC20 public token;

    // Users
    address alice;
    address bob = makeAddr("bob");
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

        // 3. Deploy the forwarder
        forwarder = new EIP3009Forwarder(address(token), "TestForwarder", "1");

        // 4. Get the domain separator
        DOMAIN_SEPARATOR = forwarder.DOMAIN_SEPARATOR();

        // 5. Fund Alice's account
        token.mint(alice, INITIAL_MINT_AMOUNT);

        // 6. Alice approves the forwarder to spend her tokens
        vm.prank(alice);
        token.approve(address(forwarder), type(uint256).max);

        // Label addresses for easier debugging
        vm.label(alice, "Alice");
        vm.label(bob, "Bob");
        vm.label(relayer, "Relayer");
        vm.label(address(token), "MockToken");
        vm.label(address(forwarder), "Forwarder");
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
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (v, r, s) = vm.sign(privateKey, digest);
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
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(RECEIVE_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (v, r, s) = vm.sign(privateKey, digest);
    }

    /**
     * @notice Signs a CancelAuthorization message.
     */
    function _signCancel(address authorizer, bytes32 nonce, uint256 privateKey)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(abi.encode(CANCEL_TYPEHASH, authorizer, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (v, r, s) = vm.sign(privateKey, digest);
    }

    function _encodeEOASignature(uint8 v, bytes32 r, bytes32 s) internal pure returns (bytes memory) {
        return abi.encodePacked(r, s, v);
    }

    // =============================================================
    //                       Success Scenarios
    // =============================================================

    function test_succeeds_transferWithAuthorization() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationUsed(alice, nonce);

        // Act: Relayer submits the transaction
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, v, r, s);

        // Assert
        assertEq(token.balanceOf(alice), INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT, "Alice's balance should decrease");
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT, "Bob's balance should increase");
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be marked as used");
    }

    function test_succeeds_transferWithAuthorization_bytesSignature() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1-bytes");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationUsed(alice, nonce);

        // Act: Relayer submits the transaction
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature);

        // Assert
        assertEq(token.balanceOf(alice), INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT, "Alice's balance should decrease");
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT, "Bob's balance should increase");
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be marked as used");
    }

    function test_succeeds_receiveWithAuthorization() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce2");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceive(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationUsed(alice, nonce);

        // Act: Bob (the recipient) submits the transaction
        vm.prank(bob);
        forwarder.receiveWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, v, r, s);

        // Assert
        assertEq(token.balanceOf(alice), INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT);
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT);
        assertTrue(forwarder.authorizationState(alice, nonce));
    }

    function test_succeeds_receiveWithAuthorization_bytesSignature() public {
        // Arrange
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce2-bytes");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceive(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationUsed(alice, nonce);

        // Act: Bob (the recipient) submits the transaction
        vm.prank(bob);
        forwarder.receiveWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature);

        // Assert
        assertEq(token.balanceOf(alice), INITIAL_MINT_AMOUNT - TRANSFER_AMOUNT);
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT);
        assertTrue(forwarder.authorizationState(alice, nonce));
    }

    function test_succeeds_cancelAuthorization() public {
        // Arrange
        bytes32 nonceToCancel = keccak256("nonce-to-cancel");
        (uint8 v, bytes32 r, bytes32 s) = _signCancel(alice, nonceToCancel, alicePrivateKey);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationCanceled(alice, nonceToCancel);

        // Act: Alice cancels the authorization
        vm.prank(alice);
        forwarder.cancelAuthorization(alice, nonceToCancel, v, r, s);

        // Assert: Nonce is used
        assertTrue(
            forwarder.authorizationState(alice, nonceToCancel), "Nonce should be marked as used after cancellation"
        );

        // Assert: Cannot use the canceled nonce for a transfer
        vm.expectRevert(EIP3009Forwarder.AuthorizationAlreadyUsed.selector);
        (v, r, s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1 hours, nonceToCancel, alicePrivateKey);
        forwarder.transferWithAuthorization(
            alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1 hours, nonceToCancel, v, r, s
        );
    }

    function test_succeeds_cancelAuthorization_bytesSignature() public {
        // Arrange
        bytes32 nonceToCancel = keccak256("nonce-to-cancel-bytes");
        (uint8 v, bytes32 r, bytes32 s) = _signCancel(alice, nonceToCancel, alicePrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationCanceled(alice, nonceToCancel);

        // Act: Alice cancels the authorization
        vm.prank(alice);
        forwarder.cancelAuthorization(alice, nonceToCancel, signature);

        // Assert: Nonce is used
        assertTrue(
            forwarder.authorizationState(alice, nonceToCancel), "Nonce should be marked as used after cancellation"
        );
    }

    function test_succeeds_transferWithAuthorization_contractWalletSignature() public {
        // Arrange
        MockERC1271Wallet wallet = new MockERC1271Wallet(alice);
        vm.label(address(wallet), "AliceContractWallet");

        token.mint(address(wallet), TRANSFER_AMOUNT);

        wallet.approveToken(token, address(forwarder), type(uint256).max);

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce-contract-wallet");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationUsed(address(wallet), nonce);

        // Act: Relayer submits the transaction
        vm.prank(relayer);
        forwarder.transferWithAuthorization(
            address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature
        );

        // Assert
        assertEq(token.balanceOf(address(wallet)), 0);
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT);
        assertTrue(forwarder.authorizationState(address(wallet), nonce));
    }

    function test_succeeds_receiveWithAuthorization_contractWalletSignature() public {
        // Arrange
        MockERC1271Wallet wallet = new MockERC1271Wallet(alice);
        vm.label(address(wallet), "AliceContractWallet");

        token.mint(address(wallet), TRANSFER_AMOUNT);

        wallet.approveToken(token, address(forwarder), type(uint256).max);

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce-contract-wallet-receive");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceive(address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationUsed(address(wallet), nonce);

        // Act: Bob (the recipient) submits the transaction
        vm.prank(bob);
        forwarder.receiveWithAuthorization(
            address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature
        );

        // Assert
        assertEq(token.balanceOf(address(wallet)), 0);
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT);
        assertTrue(forwarder.authorizationState(address(wallet), nonce));
    }

    function test_succeeds_cancelAuthorization_contractWalletSignature() public {
        // Arrange
        MockERC1271Wallet wallet = new MockERC1271Wallet(alice);
        vm.label(address(wallet), "AliceContractWallet");

        bytes32 nonceToCancel = keccak256("nonce-contract-wallet-cancel");
        (uint8 v, bytes32 r, bytes32 s) = _signCancel(address(wallet), nonceToCancel, alicePrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit EIP3009Forwarder.AuthorizationCanceled(address(wallet), nonceToCancel);

        // Act
        vm.prank(relayer);
        forwarder.cancelAuthorization(address(wallet), nonceToCancel, signature);

        // Assert
        assertTrue(forwarder.authorizationState(address(wallet), nonceToCancel));

        // Assert: cannot use the canceled nonce for a transfer
        vm.expectRevert(EIP3009Forwarder.AuthorizationAlreadyUsed.selector);
        (v, r, s) = _signTransfer(
            address(wallet), bob, TRANSFER_AMOUNT, 0, block.timestamp + 1 hours, nonceToCancel, alicePrivateKey
        );
        signature = _encodeEOASignature(v, r, s);
        forwarder.transferWithAuthorization(
            address(wallet), bob, TRANSFER_AMOUNT, 0, block.timestamp + 1 hours, nonceToCancel, signature
        );
    }

    function test_reverts_transferWithAuthorization_contractWalletSignature_invalidSignature() public {
        // Arrange
        MockERC1271Wallet wallet = new MockERC1271Wallet(alice);

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce-contract-wallet-invalid");

        uint256 bobPrivateKey = 0xB0B;
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, bobPrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        // Act & Assert
        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(
            address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature
        );
        assertFalse(forwarder.authorizationState(address(wallet), nonce));
    }

    function test_reverts_then_succeeds_transferWithAuthorization_contractWalletSignature_when_gas_stipend_increases()
        public
    {
        // Arrange
        MockERC1271WalletGasGuzzler wallet = new MockERC1271WalletGasGuzzler(alice);
        vm.label(address(wallet), "GasGuzzlingContractWallet");

        token.mint(address(wallet), TRANSFER_AMOUNT);
        wallet.approveToken(token, address(forwarder), type(uint256).max);

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce-contract-wallet-gas");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        wallet.setGasToConsume(10_000);

        // Act & Assert: too little gas stipend should fail ERC-1271 validation
        forwarder.setERC1271GasStipend(5_000);
        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(
            address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature
        );
        assertFalse(forwarder.authorizationState(address(wallet), nonce));

        // Act & Assert: increasing stipend allows success
        forwarder.setERC1271GasStipend(1_000_000);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(
            address(wallet), bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, signature
        );

        assertEq(token.balanceOf(address(wallet)), 0);
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT);
        assertTrue(forwarder.authorizationState(address(wallet), nonce));
    }

    // =============================================================
    //                       Failure Scenarios
    // =============================================================

    function test_reverts_if_nonce_reused() public {
        // Arrange: Perform a successful transfer first
        bytes32 nonce = keccak256("reused-nonce");
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(alice, bob, 1, 0, block.timestamp + 1, nonce, alicePrivateKey);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, 1, 0, block.timestamp + 1, nonce, v, r, s);

        // Act & Assert: Attempt to use the same nonce again
        vm.expectRevert(EIP3009Forwarder.AuthorizationAlreadyUsed.selector);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, 1, 0, block.timestamp + 1, nonce, v, r, s);
    }

    function test_reverts_if_signature_invalid() public {
        bytes32 nonce = keccak256("invalid-sig-nonce");
        // Sign with Bob's key, but claim it's from Alice
        uint256 bobPrivateKey = 0xB0B;
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, bobPrivateKey);

        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);
    }

    function test_reverts_if_signature_invalid_bytesSignature() public {
        bytes32 nonce = keccak256("invalid-sig-nonce-bytes");
        uint256 bobPrivateKey = 0xB0B;
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, bobPrivateKey);
        bytes memory signature = _encodeEOASignature(v, r, s);

        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, signature);
    }

    function test_reverts_if_authorization_expired() public {
        bytes32 nonce = keccak256("expired-nonce");
        uint256 validBefore = block.timestamp - 1; // Expired 1 second ago
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, validBefore, nonce, alicePrivateKey);

        vm.expectRevert(EIP3009Forwarder.AuthorizationExpired.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, validBefore, nonce, v, r, s);
    }

    function test_reverts_if_authorization_not_yet_valid() public {
        bytes32 nonce = keccak256("not-yet-valid-nonce");
        uint256 validAfter = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, validAfter, validAfter + 1, nonce, alicePrivateKey);

        vm.expectRevert(EIP3009Forwarder.AuthorizationNotYetValid.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validAfter + 1, nonce, v, r, s);
    }

    function test_reverts_if_dates_invalid() public {
        bytes32 nonce = keccak256("invalid-dates-nonce");
        uint256 validAfter = block.timestamp + 100;
        uint256 validBefore = block.timestamp + 50; // before validAfter
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);

        vm.expectRevert(EIP3009Forwarder.InvalidAuthorizationDates.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, v, r, s);
    }

    function test_reverts_if_insufficient_allowance() public {
        // Arrange: Alice approves only a small amount
        vm.prank(alice);
        token.approve(address(forwarder), TRANSFER_AMOUNT - 1);

        bytes32 nonce = keccak256("allowance-nonce");
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, alicePrivateKey);

        // Act & Assert
        vm.expectRevert(EIP3009Forwarder.InsufficientAllowance.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);
    }

    function test_reverts_if_insufficient_balance() public {
        // Arrange: Transfer more than Alice has
        uint256 excessiveAmount = INITIAL_MINT_AMOUNT + 1;
        bytes32 nonce = keccak256("balance-nonce");
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, excessiveAmount, 0, block.timestamp + 1, nonce, alicePrivateKey);

        // Act & Assert
        vm.expectRevert(EIP3009Forwarder.InsufficientBalance.selector);
        forwarder.transferWithAuthorization(alice, bob, excessiveAmount, 0, block.timestamp + 1, nonce, v, r, s);
    }

    function test_reverts_receive_if_caller_is_not_recipient() public {
        bytes32 nonce = keccak256("receive-fail-nonce");
        (uint8 v, bytes32 r, bytes32 s) =
            _signReceive(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, alicePrivateKey);

        // Act: Relayer calls, but `to` is Bob. This must fail.
        vm.prank(relayer);
        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector); // The check is `to != msg.sender`
        forwarder.receiveWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);
    }

    function test_reverts_deploy_with_zero_address_token() public {
        vm.expectRevert(EIP3009Forwarder.ZeroAddress.selector);
        new EIP3009Forwarder(address(0), "Test", "1");
    }

    function test_succeeds_owner_can_update_erc1271_gas_stipend() public {
        uint256 newGasStipend = 100_000;
        forwarder.setERC1271GasStipend(newGasStipend);
        assertEq(forwarder.erc1271GasStipend(), newGasStipend);
    }

    function test_reverts_if_non_owner_updates_erc1271_gas_stipend() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, bob));
        forwarder.setERC1271GasStipend(100_000);
    }

    function test_reverts_if_erc1271_gas_stipend_is_zero() public {
        vm.expectRevert(EIP3009Forwarder.InvalidERC1271GasStipend.selector);
        forwarder.setERC1271GasStipend(0);
    }
}
