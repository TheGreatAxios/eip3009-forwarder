// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title EIP3009Forwarder
 * @author TheGreatAxios
 * @notice A gas-less ERC-20 token forwarder using EIP-712 signatures (EOA-only).
 * @dev Implements EIP-3009 for meta-transactions.
 */
contract EIP3009Forwarder is EIP712, ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // =============================================================
    //                           State
    // =============================================================

    /**
     * @notice The immutable address of the underlying ERC-20 token.
     */
    IERC20 public immutable TOKEN;

    /**
     * @dev Mapping to track authorization nonce usage.
     * `_authorizationStates[authorizer][nonce] = true` means the nonce has been used.
     */
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    // =============================================================
    //                       EIP-712 Hashes
    // =============================================================

    /**
     * @dev EIP-712 type hash for TransferWithAuthorization.
     */
    bytes32 private constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /**
     * @dev EIP-712 type hash for ReceiveWithAuthorization.
     */
    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /**
     * @dev EIP-712 type hash for CancelAuthorization.
     */
    bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    // =============================================================
    //                           Events
    // =============================================================

    /**
     * @notice Emitted when an authorization is successfully used.
     * @param authorizer The address that signed the authorization.
     * @param nonce The unique nonce of the authorization.
     */
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /**
     * @notice Emitted when an authorization is canceled.
     * @param authorizer The address that signed the cancellation.
     * @param nonce The unique nonce of the authorization.
     */
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    // =============================================================
    //                         Custom Errors
    // =============================================================

    /// @notice The provided signature is invalid or does not match the authorizer.
    error InvalidSignature();
    /// @notice The authorization is not yet valid (block.timestamp < validAfter).
    error AuthorizationNotYetValid();
    /// @notice The authorization has expired (block.timestamp > validBefore).
    error AuthorizationExpired();
    /// @notice The authorization's nonce has already been used or canceled.
    error AuthorizationAlreadyUsed();
    /// @notice An address parameter was the zero address.
    error ZeroAddress();
    /// @notice The `from` address has not approved the forwarder for sufficient tokens.
    error InsufficientAllowance();
    /// @notice The `from` address does not have sufficient token balance.
    error InsufficientBalance();
    /// @notice The provided `validAfter` timestamp is after `validBefore`.
    error InvalidAuthorizationDates();
    /// @notice The signature length is invalid (not 65 bytes for ECDSA).
    error InvalidSignatureLength();

    // =============================================================
    //                        Constants
    // =============================================================

    /**
     * @dev Half of the secp256k1 curve order.
     * Used to prevent signature malleability by ensuring s-value is in the lower half.
     * secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
     * This value is secp256k1n / 2, preventing malleability where (r, s) and (r, n-s) are both valid.
     */
    uint256 internal constant SECP256K1N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // =============================================================
    //                         Constructor
    // =============================================================

    /**
     * @notice Initializes the forwarder contract.
     * @param _token The address of the ERC-20 token this forwarder will manage.
     * @param _name The name for the EIP-712 domain separator.
     * @param _version The version for the EIP-712 domain separator.
     */
    constructor(address _token, string memory _name, string memory _version) EIP712(_name, _version) {
        if (_token == address(0)) revert ZeroAddress();
        TOKEN = IERC20(_token);
    }

    // =============================================================
    //                   Authorization Functions
    // =============================================================

    /**
     * @notice Executes a token transfer authorized by an EIP-712 signature.
     *
     * @param from The address of the token holder authorizing the transfer.
     * @param to The address of the recipient.
     * @param value The amount of tokens to transfer.
     * @param validAfter The Unix timestamp after which the authorization is valid.
     * @param validBefore The Unix timestamp before which the authorization expires.
     * @param nonce A unique, user-generated value to prevent replay attacks.
     * @param v The recovery ID of the ECDSA signature.
     * @param r The r-value of the ECDSA signature.
     * @param s The s-value of the ECDSA signature.
     */
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
    ) external nonReentrant {
        if (from == address(0) || to == address(0)) revert ZeroAddress();

        if (validAfter > validBefore) revert InvalidAuthorizationDates();
        if (block.timestamp < validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp > validBefore) revert AuthorizationExpired();

        if (_authorizationStates[from][nonce]) revert AuthorizationAlreadyUsed();

        if (uint256(s) > SECP256K1N_HALF) {
            revert InvalidSignature();
        }

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );

        bytes32 hash = _hashTypedDataV4(structHash);

        address signer = hash.recover(v, r, s);

        if (signer != from) revert InvalidSignature();

        uint256 currentAllowance = TOKEN.allowance(from, address(this));
        if (currentAllowance < value) revert InsufficientAllowance();

        uint256 currentBalance = TOKEN.balanceOf(from);
        if (currentBalance < value) revert InsufficientBalance();

        _markNonceUsed(from, nonce);
        emit AuthorizationUsed(from, nonce);

        TOKEN.safeTransferFrom(from, to, value);
    }

    /**
     * @notice Executes a token transfer where the recipient must be the transaction submitter.
     * @dev The `to` parameter MUST match `msg.sender`.
     *
     * @param from The address of the token holder authorizing the transfer.
     * @param to The address of the recipient (must equal msg.sender).
     * @param value The amount of tokens to transfer.
     * @param validAfter The Unix timestamp after which the authorization is valid.
     * @param validBefore The Unix timestamp before which the authorization expires.
     * @param nonce A unique, user-generated value to prevent replay attacks.
     * @param v The recovery ID of the ECDSA signature.
     * @param r The r-value of the ECDSA signature.
     * @param s The s-value of the ECDSA signature.
     */
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
    ) external nonReentrant {
        if (to != msg.sender) revert InvalidSignature();
        if (from == address(0)) revert ZeroAddress();

        if (validAfter > validBefore) revert InvalidAuthorizationDates();
        if (block.timestamp < validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp > validBefore) revert AuthorizationExpired();

        if (_authorizationStates[from][nonce]) revert AuthorizationAlreadyUsed();

        if (uint256(s) > SECP256K1N_HALF) {
            revert InvalidSignature();
        }

        bytes32 structHash =
            keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce));

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(v, r, s);

        if (signer != from) revert InvalidSignature();

        uint256 currentAllowance = TOKEN.allowance(from, address(this));
        if (currentAllowance < value) revert InsufficientAllowance();

        uint256 currentBalance = TOKEN.balanceOf(from);
        if (currentBalance < value) revert InsufficientBalance();

        _markNonceUsed(from, nonce);
        emit AuthorizationUsed(from, nonce);

        TOKEN.safeTransferFrom(from, to, value);
    }

    /**
     * @notice Cancels an unused authorization, preventing it from being used in the future.
     * @dev The authorizer signs a cancellation message to invalidate a specific nonce.
     *
     * @param authorizer The address canceling the authorization.
     * @param nonce The nonce of the authorization to cancel.
     * @param v The recovery ID of the ECDSA signature.
     * @param r The r-value of the ECDSA signature.
     * @param s The s-value of the ECDSA signature.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        if (_authorizationStates[authorizer][nonce]) revert AuthorizationAlreadyUsed();

        if (uint256(s) > SECP256K1N_HALF) {
            revert InvalidSignature();
        }

        // forge-lint: disable-start(asm-keccak256)
        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce));
        // forge-lint: disable-end(asm-keccak256)

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(v, r, s);

        if (signer != authorizer) revert InvalidSignature();

        // Mark nonce as used
        _markNonceUsed(authorizer, nonce);
        emit AuthorizationCanceled(authorizer, nonce);
    }

    // =============================================================
    //                       View Functions
    // =============================================================

    /**
     * @notice Checks whether an authorization has been used or canceled.
     * @param authorizer The address of the authorizer.
     * @param nonce The nonce of the authorization.
     * @return bool True if the nonce has been used, false otherwise.
     */
    function authorizationState(address authorizer, bytes32 nonce) public view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    // =============================================================
    //                   Internal Functions
    // =============================================================

    /**
     * @dev Internal function to mark a nonce as used.
     * @param authorizer The address of the authorizer.
     * @param nonce The nonce to mark as used.
     */
    function _markNonceUsed(address authorizer, bytes32 nonce) internal {
        _authorizationStates[authorizer][nonce] = true;
    }

    /**
     * @notice Returns the EIP-712 domain separator for this contract.
     * @dev The domain separator is unique to the contract and chain.
     * @return The 32-byte domain separator hash.
     */
    // forge-lint: disable-start(mixed-case-variable)
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // forge-lint: disable-end(mixed-case-variable)

    /**
     * @notice Returns the underlying token address.
     * @return The address of the ERC-20 token.
     */
    function underlyingToken() external view returns (address) {
        return address(TOKEN);
    }

    /**
     * @notice Checks if an owner has approved this contract to spend a certain amount.
     * @param owner The address of the token owner.
     * @param amount The amount to check for allowance.
     * @return bool True if the allowance is sufficient, false otherwise.
     */
    function hasApproval(address owner, uint256 amount) external view returns (bool) {
        return TOKEN.allowance(owner, address(this)) >= amount;
    }

    /**
     * @notice Gets the current allowance an owner has granted to this contract.
     * @param owner The address of the token owner.
     * @return The allowance amount.
     */
    function getAllowance(address owner) external view returns (uint256) {
        return TOKEN.allowance(owner, address(this));
    }
}
