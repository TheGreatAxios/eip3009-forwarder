// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EIP3009Forwarder} from "../src/EIP3009Forwarder.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

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

    // Security Constants
    uint256 internal constant SECP256K1N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

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

    // =============================================================
    //                 Nonce Griefing Protection Tests
    // =============================================================

    /**
     * @notice CRITICAL: Verify nonce is NOT marked used when allowance check fails.
     * This prevents nonce griefing attacks where malicious relayers could burn nonces
     * by submitting transactions with insufficient approval.
     */
    function testNonceNotMarkedUsed_WhenInsufficientAllowance() public {
        // Arrange: Set approval to zero
        vm.prank(alice);
        token.approve(address(forwarder), 0);

        bytes32 nonce = keccak256("grief-allowance-nonce");
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, alicePrivateKey);

        // Act: Attempt transfer with insufficient allowance
        vm.expectRevert(EIP3009Forwarder.InsufficientAllowance.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);

        // Assert: Nonce should NOT be marked as used
        assertFalse(
            forwarder.authorizationState(alice, nonce), "Nonce should remain unused after failed allowance check"
        );

        // Assert: Same nonce can still be used after fixing approval
        vm.prank(alice);
        token.approve(address(forwarder), type(uint256).max);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be usable after approval fix");
    }

    /**
     * @notice CRITICAL: Verify nonce is NOT marked used when balance check fails.
     * This prevents nonce griefing where attackers could burn nonces by submitting
     * transactions for amounts exceeding the sender's balance.
     */
    function testNonceNotMarkedUsed_WhenInsufficientBalance() public {
        // Arrange: Alice has valid approval but tries to transfer more than she owns
        vm.prank(alice);
        token.approve(address(forwarder), type(uint256).max);

        bytes32 nonce = keccak256("grief-balance-nonce");

        // Sign for amount exceeding Alice's balance
        uint256 excessiveAmount = INITIAL_MINT_AMOUNT + 1;
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, excessiveAmount, 0, block.timestamp + 1, nonce, alicePrivateKey);

        // Act: Attempt transfer with insufficient balance
        vm.expectRevert(EIP3009Forwarder.InsufficientBalance.selector);
        forwarder.transferWithAuthorization(alice, bob, excessiveAmount, 0, block.timestamp + 1, nonce, v, r, s);

        // Assert: Nonce should NOT be marked as used
        assertFalse(forwarder.authorizationState(alice, nonce), "Nonce should remain unused after failed balance check");

        // Assert: Same nonce can be used with valid amount (need new signature for different amount)
        bytes32 newNonce = keccak256("new-nonce-after-balance-fix");
        (v, r, s) = _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, newNonce, alicePrivateKey);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, newNonce, v, r, s);
        assertTrue(forwarder.authorizationState(alice, newNonce), "New nonce should be usable");
    }

    /**
     * @notice CRITICAL: Verify nonce is NOT marked used when signature is invalid.
     * Prevents nonce griefing through invalid signature submissions.
     */
    function testNonceNotMarkedUsed_WhenSignatureInvalid() public {
        bytes32 nonce = keccak256("grief-sig-nonce");
        uint256 bobPrivateKey = 0xB0B;

        // Sign with wrong private key
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, bobPrivateKey);

        // Act: Attempt with invalid signature
        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);

        // Assert: Nonce should NOT be marked as used
        assertFalse(
            forwarder.authorizationState(alice, nonce), "Nonce should remain unused after failed signature check"
        );

        // Assert: Valid signature with same nonce should work
        (v, r, s) = _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, alicePrivateKey);
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be usable with valid signature");
    }

    // =============================================================
    //              Signature Malleability Tests
    // =============================================================

    /**
     * @notice CRITICAL: Verify high-s value signatures are rejected in transferWithAuthorization.
     * EIP-2 requires s <= secp256k1n/2 to prevent signature malleability.
     */
    function testRevertWhen_HighSValue_Transfer() public {
        bytes32 nonce = keccak256("highs-transfer-nonce");

        // Get a valid signature first
        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, alicePrivateKey);

        // If s is low, convert it to high-s (malformed signature)
        if (uint256(s) <= SECP256K1N_HALF) {
            // s' = order - s (creates the high-s equivalent)
            s = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
            // v needs to be adjusted: if v was 27, make it 28, and vice versa
            v = v == 27 ? 28 : 27;
        }

        // Act & Assert: High-s signature should revert
        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);
    }

    /**
     * @notice CRITICAL: Verify high-s value signatures are rejected in receiveWithAuthorization.
     */
    function testRevertWhen_HighSValue_Receive() public {
        bytes32 nonce = keccak256("highs-receive-nonce");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceive(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, alicePrivateKey);

        // Convert to high-s if needed
        if (uint256(s) <= SECP256K1N_HALF) {
            s = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
            v = v == 27 ? 28 : 27;
        }

        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        forwarder.receiveWithAuthorization(alice, bob, TRANSFER_AMOUNT, 0, block.timestamp + 1, nonce, v, r, s);
    }

    /**
     * @notice CRITICAL: Verify high-s value signatures are rejected in cancelAuthorization.
     */
    function testRevertWhen_HighSValue_Cancel() public {
        bytes32 nonce = keccak256("highs-cancel-nonce");

        (uint8 v, bytes32 r, bytes32 s) = _signCancel(alice, nonce, alicePrivateKey);

        // Convert to high-s if needed
        if (uint256(s) <= SECP256K1N_HALF) {
            s = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
            v = v == 27 ? 28 : 27;
        }

        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        vm.prank(alice);
        forwarder.cancelAuthorization(alice, nonce, v, r, s);
    }

    // =============================================================
    //                   Boundary Value Tests
    // =============================================================

    /**
     * @notice Edge case: Verify zero-value transfers work correctly.
     * Tests boundary condition where value = 0.
     */
    function testSucceeds_ZeroValueTransfer() public {
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("zero-value-nonce");

        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(alice, bob, 0, validAfter, validBefore, nonce, alicePrivateKey);

        // Act: Zero-value transfer should succeed
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, 0, validAfter, validBefore, nonce, v, r, s);

        // Assert: Nonce is used, balances unchanged
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be marked as used");
        assertEq(token.balanceOf(alice), INITIAL_MINT_AMOUNT, "Alice's balance should be unchanged");
        assertEq(token.balanceOf(bob), 0, "Bob's balance should remain zero");
    }

    /**
     * @notice Edge case: Verify validAfter == validBefore works (single timestamp window).
     * Tests boundary condition where the valid window is exactly one block timestamp.
     */
    function testSucceeds_SameTimestampWindow() public {
        uint256 targetTime = block.timestamp + 100;
        uint256 validAfter = targetTime;
        uint256 validBefore = targetTime; // Same as validAfter
        bytes32 nonce = keccak256("same-timestamp-nonce");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);

        // Warp to exact timestamp
        vm.warp(targetTime);

        // Act: Should succeed at exact timestamp
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, v, r, s);

        // Assert
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be marked as used");
        assertEq(token.balanceOf(bob), TRANSFER_AMOUNT, "Bob should receive tokens");
    }

    /**
     * @notice Edge case: Verify transfers work with max uint256 approval.
     * Tests the special case where allowance is set to type(uint256).max.
     */
    function testSucceeds_MaxAllowance() public {
        // Arrange: Set max approval (already set in setUp, but explicitly setting here for clarity)
        vm.prank(alice);
        token.approve(address(forwarder), type(uint256).max);

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("max-allowance-nonce");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransfer(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, alicePrivateKey);

        // Act: Transfer with max approval should succeed
        vm.prank(relayer);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, v, r, s);

        // Assert: Approval should not decrease (type(uint256).max is special case in ERC20)
        assertEq(token.allowance(alice, address(forwarder)), type(uint256).max, "Max allowance should not decrease");
        assertTrue(forwarder.authorizationState(alice, nonce), "Nonce should be marked as used");
    }

    // =============================================================
    //                 Domain Separator Tests
    // =============================================================

    /**
     * @notice Verify EIP-712 domain separator matches expected format.
     * Ensures proper domain separation for replay protection.
     */
    function testDomainSeparator_MatchesExpected() public {
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TestForwarder")), // name
                keccak256(bytes("1")), // version
                block.chainid, // chainId
                address(forwarder) // verifyingContract
            )
        );

        assertEq(
            forwarder.DOMAIN_SEPARATOR(), expectedDomainSeparator, "Domain separator should match EIP-712 specification"
        );
    }

    /**
     * @notice Fuzz test: Demonstrate cross-chain replay protection.
     * Signatures from one chainId should not work on another.
     */
    function testFuzz_DomainPreventsCrossChainReplay(uint256 chainId) public {
        // Exclude current chain and chainId 0
        vm.assume(chainId != block.chainid);
        vm.assume(chainId != 0);

        // Create a signature for a different chain
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("cross-chain-nonce");

        // Get signature with wrong chainId
        bytes32 wrongDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TestForwarder")),
                keccak256(bytes("1")),
                chainId, // Wrong chainId
                address(forwarder)
            )
        );

        // Sign with wrong domain separator
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_TYPEHASH, alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", wrongDomainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);

        // Assert: Signature from different chain should fail
        vm.expectRevert(EIP3009Forwarder.InvalidSignature.selector);
        forwarder.transferWithAuthorization(alice, bob, TRANSFER_AMOUNT, validAfter, validBefore, nonce, v, r, s);

        // Assert: Nonce should NOT be marked used (can still be used with correct chain signature)
        assertFalse(forwarder.authorizationState(alice, nonce), "Nonce should remain unused");
    }
}
