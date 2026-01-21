// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {EIP3009Forwarder} from "./EIP3009Forwarder.sol";

/**
 * @title EIP3009ForwarderExtended
 * @author TheGreatAxios
 * @notice Extended forwarder with ERC-1271 smart contract wallet support.
 * @dev Extends EIP3009Forwarder to support signatures from smart contracts implementing ERC-1271.
 *      Contract wallets must be whitelisted before use.
 */
contract EIP3009ForwarderExtended is EIP3009Forwarder {
    using SafeERC20 for IERC20;

    // =============================================================
    //                           Constants
    // =============================================================

    /// @dev Magic value for ERC-1271 signature validation success (bytes4(keccak256("isValidSignature(bytes32,bytes)")))
    bytes4 private constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @dev Default gas limit for ERC-1271 validation calls (prevents griefing)
    uint256 private constant DEFAULT_ERC1271_GAS_LIMIT = 100000;

    // =============================================================
    //                           State
    // =============================================================

    /// @dev Mapping of whitelisted smart contract wallets (required for ERC-1271 signatures)
    mapping(address => bool) private _whitelistedWallets;

    /// @dev Whether the wallet whitelist is enabled
    bool private _whitelistEnabled;

    /// @dev Address with admin privileges to manage whitelist and settings
    address private _admin;

    /// @dev Pending admin address for two-step transfer process
    address private _pendingAdmin;

    /// @dev Current gas limit for ERC-1271 signature validation calls
    uint256 private _erc1271GasLimit;

    // =============================================================
    //                         Custom Errors
    // =============================================================

    error ERC1271ValidationFailed();
    error WalletNotWhitelisted();
    error NotAdmin();
    error InvalidERC1271Return();
    error InvalidGasLimit();
    error ZeroValue();

    // =============================================================
    //                           Events
    // =============================================================

    event WalletWhitelistChanged(address indexed wallet, bool whitelisted);
    event WhitelistEnabledChanged(bool enabled);
    event AdminTransferInitiated(address indexed currentAdmin, address indexed pendingAdmin);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event AdminTransferRenounced(address indexed currentAdmin);
    event ERC1271GasLimitChanged(uint256 newGasLimit);

    // =============================================================
    //                         Constructor
    // =============================================================

    /**
     * @notice Initializes the extended forwarder with ERC-1271 support.
     * @param _token The address of the ERC-20 token.
     * @param _name The name for the EIP-712 domain separator.
     * @param _version The version for the EIP-712 domain separator.
     * @param _enableWhitelist Whether to enable the wallet whitelist.
     */
    constructor(address _token, string memory _name, string memory _version, bool _enableWhitelist)
        EIP3009Forwarder(_token, _name, _version)
    {
        _admin = msg.sender;
        _whitelistEnabled = _enableWhitelist;
        _erc1271GasLimit = DEFAULT_ERC1271_GAS_LIMIT;
        emit WhitelistEnabledChanged(_enableWhitelist);
    }

    // =============================================================
    //                   Modifiers
    // =============================================================

    modifier onlyAdmin() {
        if (msg.sender != _admin) revert NotAdmin();
        _;
    }

    // =============================================================
    //                 Administrative Functions
    // =============================================================

    /**
     * @notice Adds or removes a wallet from the whitelist.
     * @dev Only callable by admin.
     * @param wallet The address of the wallet to modify.
     * @param whitelisted True to add to whitelist, false to remove.
     */
    function setWhitelistedWallet(address wallet, bool whitelisted) external onlyAdmin {
        _whitelistedWallets[wallet] = whitelisted;
        emit WalletWhitelistChanged(wallet, whitelisted);
    }

    /**
     * @notice Enables or disables the wallet whitelist.
     * @dev Only callable by admin.
     * @param enabled True to enable whitelist, false to disable.
     */
    function setWhitelistEnabled(bool enabled) external onlyAdmin {
        _whitelistEnabled = enabled;
        emit WhitelistEnabledChanged(enabled);
    }

    /**
     * @notice Initiates transfer of admin privileges to a new address.
     * @dev Only callable by current admin. The new admin must accept the transfer.
     * @param newAdmin The address of the new admin.
     */
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        _pendingAdmin = newAdmin;
        emit AdminTransferInitiated(_admin, newAdmin);
    }

    /**
     * @notice Accepts the pending admin transfer.
     * @dev Only callable by the pending admin address.
     */
    function acceptAdmin() external {
        if (msg.sender != _pendingAdmin) revert NotAdmin();
        address oldAdmin = _admin;
        _admin = _pendingAdmin;
        _pendingAdmin = address(0);
        emit AdminTransferred(oldAdmin, _admin);
    }

    /**
     * @notice Renounces the pending admin transfer.
     * @dev Only callable by current admin to cancel a pending transfer.
     */
    function renounceAdminTransfer() external onlyAdmin {
        _pendingAdmin = address(0);
        emit AdminTransferRenounced(_admin);
    }

    /**
     * @notice Sets the gas limit for ERC-1271 signature validation.
     * @dev Only callable by admin. Prevents gas griefing from malicious wallets.
     * @param newGasLimit The new gas limit (must be > 0 and <= 50000).
     */
    function setERC1271GasLimit(uint256 newGasLimit) external onlyAdmin {
        if (newGasLimit == 0) revert ZeroValue();
        if (newGasLimit > 50000) revert InvalidGasLimit();
        _erc1271GasLimit = newGasLimit;
        emit ERC1271GasLimitChanged(newGasLimit);
    }

    // =============================================================
    //              ERC-1271 Authorization Functions
    // =============================================================

    /**
     * @notice Executes a transfer using ERC-1271 signature from a smart contract wallet.
     *
     * @param from The address of the token holder.
     * @param to The address of the recipient.
     * @param value The amount of tokens to transfer.
     * @param validAfter The Unix timestamp after which the authorization is valid.
     * @param validBefore The Unix timestamp before which the authorization expires.
     * @param nonce A unique, user-generated value to prevent replay attacks.
     * @param signature The ERC-1271 signature bytes.
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external nonReentrant {
        if (authorizationState(from, nonce)) revert AuthorizationAlreadyUsed();

        if (from == address(0) || to == address(0)) revert ZeroAddress();
        if (validAfter > validBefore) revert InvalidAuthorizationDates();
        if (block.timestamp < validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp > validBefore) revert AuthorizationExpired();

        bool isFromContract = _isContract(from);
        if (isFromContract) {
            _validateERC1271Wallet(from);
            _validateERC1271Signature(from, to, value, validAfter, validBefore, nonce, signature);
        } else {
            if (signature.length != 65) revert InvalidSignature();
            (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signature);
            if (uint256(s) > SECP256K1N_HALF) revert InvalidSignature();

            bytes32 structHash = keccak256(
                abi.encode(
                    keccak256(
                        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
                    ),
                    from,
                    to,
                    value,
                    validAfter,
                    validBefore,
                    nonce
                )
            );
            bytes32 hash = _hashTypedDataV4(structHash);
            address signer = _recover(hash, v, r, s);
            if (signer != from) revert InvalidSignature();
        }

        uint256 currentAllowance = TOKEN.allowance(from, address(this));
        if (currentAllowance < value) revert InsufficientAllowance();
        uint256 currentBalance = TOKEN.balanceOf(from);
        if (currentBalance < value) revert InsufficientBalance();

        _markNonceUsed(from, nonce);
        emit AuthorizationUsed(from, nonce);

        TOKEN.safeTransferFrom(from, to, value);
    }

    /**
     * @notice Executes a receive authorization using ERC-1271 signature.
     *
     * @param from The address of the token holder.
     * @param to The address of the recipient (must equal msg.sender).
     * @param value The amount of tokens to transfer.
     * @param validAfter The Unix timestamp after which the authorization is valid.
     * @param validBefore The Unix timestamp before which the authorization expires.
     * @param nonce A unique, user-generated value to prevent replay attacks.
     * @param signature The ERC-1271 signature bytes.
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external nonReentrant {
        if (to != msg.sender) revert InvalidSignature();
        if (authorizationState(from, nonce)) revert AuthorizationAlreadyUsed();
        if (from == address(0)) revert ZeroAddress();
        if (validAfter > validBefore) revert InvalidAuthorizationDates();
        if (block.timestamp < validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp > validBefore) revert AuthorizationExpired();

        bool isFromContract = _isContract(from);
        if (isFromContract) {
            _validateERC1271Wallet(from);
            _validateERC1271Signature(from, to, value, validAfter, validBefore, nonce, signature);
        } else {
            if (signature.length != 65) revert InvalidSignature();
            (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signature);
            if (uint256(s) > SECP256K1N_HALF) revert InvalidSignature();

            bytes32 structHash = keccak256(
                abi.encode(
                    keccak256(
                        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
                    ),
                    from,
                    to,
                    value,
                    validAfter,
                    validBefore,
                    nonce
                )
            );
            bytes32 hash = _hashTypedDataV4(structHash);
            address signer = _recover(hash, v, r, s);
            if (signer != from) revert InvalidSignature();
        }

        uint256 currentAllowance = TOKEN.allowance(from, address(this));
        if (currentAllowance < value) revert InsufficientAllowance();
        uint256 currentBalance = TOKEN.balanceOf(from);
        if (currentBalance < value) revert InsufficientBalance();

        _markNonceUsed(from, nonce);
        emit AuthorizationUsed(from, nonce);

        TOKEN.safeTransferFrom(from, to, value);
    }

    /**
     * @notice Cancels an authorization using ERC-1271 signature.
     * @dev Allows smart contract wallets to cancel authorizations.
     *
     * @param authorizer The address canceling the authorization.
     * @param nonce The nonce of the authorization to cancel.
     * @param signature The ERC-1271 signature bytes.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) external nonReentrant {
        if (authorizationState(authorizer, nonce)) revert AuthorizationAlreadyUsed();

        bool isAuthorizerContract = _isContract(authorizer);
        if (isAuthorizerContract) {
            _validateERC1271Wallet(authorizer);
            bytes32 cancelHash = keccak256(
                abi.encode(keccak256("CancelAuthorization(address authorizer,bytes32 nonce)"), authorizer, nonce)
            );
            _validateERC1271SignatureHash(authorizer, cancelHash, signature);
        } else {
            if (signature.length != 65) revert InvalidSignature();
            (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signature);
            if (uint256(s) > SECP256K1N_HALF) revert InvalidSignature();

            bytes32 structHash = keccak256(
                abi.encode(keccak256("CancelAuthorization(address authorizer,bytes32 nonce)"), authorizer, nonce)
            );
            bytes32 hash = _hashTypedDataV4(structHash);
            address signer = _recover(hash, v, r, s);
            if (signer != authorizer) revert InvalidSignature();
        }

        _markNonceUsed(authorizer, nonce);
        emit AuthorizationCanceled(authorizer, nonce);
    }

    // =============================================================
    //                       View Functions
    // =============================================================

    /**
     * @notice Checks if a wallet is whitelisted.
     * @param wallet The address to check.
     * @return True if whitelisted, false otherwise.
     */
    function isWhitelistedWallet(address wallet) external view returns (bool) {
        return _whitelistedWallets[wallet];
    }

    /**
     * @notice Checks if the whitelist is enabled.
     * @return True if enabled, false otherwise.
     */
    function isWhitelistEnabled() external view returns (bool) {
        return _whitelistEnabled;
    }

    /**
     * @notice Returns the current admin address.
     * @return The admin address.
     */
    function getAdmin() external view returns (address) {
        return _admin;
    }

    // =============================================================
    //                   Internal Functions
    // =============================================================

    /// @dev Checks if an address is a contract (has code).
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    /// @dev Validates that a contract wallet is whitelisted.
    function _validateERC1271Wallet(address wallet) internal view {
        if (!_whitelistedWallets[wallet]) {
            revert WalletNotWhitelisted();
        }
    }

    /// @dev Validates an ERC-1271 signature for a specific hash using staticcall with gas limit.
    function _validateERC1271SignatureHash(address wallet, bytes32 hash, bytes memory signature) internal view {
        (bool success, bytes memory data) = wallet.staticcall{gas: _erc1271GasLimit}(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
        );

        if (!success) revert ERC1271ValidationFailed();
        if (data.length < 32) revert InvalidERC1271Return();

        bytes4 magicValue;
        assembly {
            magicValue := mload(add(data, 32))
        }

        if (magicValue != ERC1271_MAGIC_VALUE) revert ERC1271ValidationFailed();
    }

    /// @dev Validates an ERC-1271 signature for a transfer authorization.
    function _validateERC1271Signature(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) internal view {
        if (signature.length < 65) revert InvalidSignature();

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
                ),
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        _validateERC1271SignatureHash(from, hash, signature);
    }

    /// @dev Splits a bytes signature into v, r, s components.
    function _splitSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        if (signature.length != 65) revert InvalidSignature();

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
    }

    /// @dev Recovers the signer from a signature hash.
    function _recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address signer) {
        signer = ecrecover(hash, v, r, s);
    }
}
