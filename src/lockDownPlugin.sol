// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {BasePluginWithEventMetadata, PluginMetadata} from "./Base.sol";
import {ISafe} from "@safe/interfaces/Accounts.sol";
import {SafeProtocolManager} from "@safe/SafeProtocolManager.sol";
import {SafeProtocolAction, SafeTransaction} from "@safe/DataTypes.sol";
import {ISafeProtocolHooks} from "@safe/interfaces/Integrations.sol";
import {ISafeProtocolRegistry} from "@safe/interfaces/Registry.sol";
import "@safe/Safe.sol";

// import {MODULE_TYPE_HOOKS} from "@safe-global/safe-core-protocol/common/Constants.sol";

contract Plugin is BasePluginWithEventMetadata {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant CO_ADMIN_ROLE = keccak256("CO_ADMIN_ROLE");

    SafeProtocolManager public manager;
    Safe private safe;

    ISafeProtocolRegistry public immutable registry;
    mapping(address => mapping(bytes4 => bool)) public denyListMethods;
    mapping(address => mapping(address => bool)) public denyListAddresses;
    mapping(Safe => mapping(bytes32 => address)) public mappedRoles;
    uint8 public requiresPermissions = 2;

    error NotSigner(Safe safe, address signer_1, address signer_2);
    error NotRegistered(Safe safe);

    // The constructor
    constructor(
        address _manager,
        address _registry
    )
        BasePluginWithEventMetadata(
            PluginMetadata({
                name: "lockDown Plugin",
                version: "1.0.0",
                requiresRootAccess: false,
                iconUrl: "",
                appUrl: ""
            })
        )
    {
        manager = SafeProtocolManager(_manager);
        registry = ISafeProtocolRegistry(_registry);
    }

    function isSigner(Safe _safe, address _signer) private view returns (bool) {
        address[] memory signers = _safe.getOwners();
        bool isOwner;
        for (uint256 i; i < signers.length; i++) {
            if (signers[i] == _signer) {
                isOwner = true;
                break;
            }
        }
        if (!isOwner) {
            return false;
        }
        return true;
    }

    modifier plugEnabled(Safe _safe) {
        if (!manager.isPluginEnabled(address(_safe), address(this))) {
            revert NotRegistered(_safe);
        }
        _;
    }

    function setUp(
        Safe _safe,
        address AdminSigner,
        address semi_admin_signer
    ) public plugEnabled(_safe) {
        if (
            !isSigner(_safe, AdminSigner) || !isSigner(_safe, semi_admin_signer)
        ) {
            revert NotSigner(_safe, AdminSigner, semi_admin_signer);
        }
        mappedRoles[_safe][ADMIN_ROLE] = AdminSigner;
        mappedRoles[_safe][CO_ADMIN_ROLE] = semi_admin_signer;
    }

    function checkRole(Safe _safe) private view {
        address safeAdmin = mappedRoles[_safe][ADMIN_ROLE];
        address safeCoAdmin = mappedRoles[_safe][CO_ADMIN_ROLE];
        if (msg.sender != safeAdmin || msg.sender != safeCoAdmin) {
            revert NotSigner(_safe, safeAdmin, safeCoAdmin);
        }
    }

    function addToDenyListMethods(Safe _safe, bytes4 method) public {
        checkRole(_safe);
        denyListMethods[address(_safe)][method] = true;
    }

    function removeFromDenyListMethods(Safe _safe, bytes4 method) public {
        checkRole(_safe);
        denyListMethods[address(_safe)][method] = false;
    }

    function addToDenyListAddresses(
        Safe _safe,
        address _blackListedAddress
    ) public {
        checkRole(_safe);
        denyListAddresses[address(_safe)][_blackListedAddress] = true;
    }

    function removeFromDenyListAddresses(
        Safe _safe,
        address _blackListedAddress
    ) public {
        checkRole(_safe);
        denyListAddresses[address(_safe)][_blackListedAddress] = false;
    }

    /**
     * @notice A function that will be called before the execution of a transaction if the hooks are enabled
     * @dev Add custom logic in this function to validate the pre-state and contents of transaction for non-root access.
     * @param account Address of the account
     * @param tx A struct of type SafeTransaction that contains the details of the transaction.
     * @param executionType uint256
     * @param executionMeta Arbitrary length of bytes
     * @return preCheckData bytes
     */
    function preCheck(
        address account,
        SafeTransaction calldata tx,
        uint256 executionType,
        bytes calldata executionMeta
    ) external returns (bytes memory preCheckData) {
        // SafeProtocolAction[] memory actions = tx.actions;
        // uint256 length = actions.length;
        address address_to;
        bytes4 _method;
        {
            (address to, , bytes memory data, , , , , , , ) = abi.decode(
                executionMeta,
                (
                    address,
                    uint256,
                    bytes,
                    uint256,
                    uint256,
                    uint256,
                    address,
                    address,
                    bytes,
                    address
                )
            );
            (address_to, _method) = ExtractorAndCheckoor(data);

            if (
                denyListMethods[account][_method] ||
                denyListAddresses[account][to] ||
                denyListAddresses[account][address_to]
            ) {
                SafeTransaction memory _emergancyTx = constructEmergancyTx(
                    account
                );
                manager.executeTransaction(ISafe(account), _emergancyTx);
            }
        }
    }

    function fetchOwners(
        address payable _safe
    ) public view returns (address[] memory) {
        return Safe(_safe).getOwners();
    }

    function constructEmergancyTx(
        address _Safe
    ) private view returns (SafeTransaction memory) {
        address[] memory owners = fetchOwners(payable(_Safe));
        uint256 signerCount = owners.length;
        uint256 newThreshold = (signerCount * 70) / 100; // 70% of signers
        uint256 _nonce;

        bytes memory data = abi.encodeWithSignature(
            "changeThreshold(uint256)",
            newThreshold
        );

        SafeProtocolAction memory action = SafeProtocolAction({
            to: payable(_Safe),
            value: 0,
            data: data
        });

        // Create an array of SafeProtocolAction structs and add the action to it
        SafeProtocolAction[] memory actions;
        actions[0] = action;
        _nonce = Safe(payable(_Safe)).nonce();
        // Prepare a SafeTransaction struct for changing the threshold
        SafeTransaction memory transactionForChangeThreshold = SafeTransaction({
            // safe: _Safe,
            actions: actions,
            nonce: _nonce + 1,
            metadataHash: "" // You can set this to any string you want
        });
        return transactionForChangeThreshold;
    }

    function postCheck(
        address account,
        bool success,
        bytes calldata preCheckData
    ) external {}

    function ExtractorAndCheckoor(
        bytes memory data
    ) public pure returns (address, bytes4) {
        bytes4 funcSig;
        address to;
        //Function to extract the to address for typical ERC standard funcs
        assembly {
            // Shift right by 224 bits to retain only the first 4 bytes
            funcSig := shr(224, mload(add(data, 0x20)))
            switch funcSig
            case 0x095ea7b3 {
                // Method ID for 'approve'
                to := mload(add(data, 0x30)) // located 48th bit
                to := shr(96, to)
            }
            case 0x23b872dd {
                // Method ID for 'transferFrom'
                to := mload(add(data, 0x50)) // located at the 80th bit
                to := shr(96, to)
            }
            case 0xa9059cbb {
                // Method ID for 'transfer'
                to := mload(add(data, 0x30)) // located 48th bit
                to := shr(96, to)
            }
            case 0x39509351 {
                // Method ID for 'increaseAllowance'
                to := mload(add(data, 0x30)) // located 48th bit
                to := shr(96, to)
            }
            case 0xd505accf {
                // Method ID for 'permit'
                to := mload(add(data, 0x50)) // located at the 80th bit
                to := shr(96, to)
            }
            case 0x42842e0e {
                // Method ID for 'safeTransferFrom(address,address,uint256)'
                to := mload(add(data, 0x50)) // located at the 80th bit
                to := shr(96, to)
            }
            case 0xb88d4fde {
                // Method ID for 'safeTransferFrom(address,address,uint256,bytes)'
                to := mload(add(data, 0x50)) // located at the 80th bit
                to := shr(96, to)
            }
            case 0xa22cb465 {
                // Method ID for 'setApprovalForAll(address,bool)'
                to := mload(add(data, 0x30)) // located 48th bit
                to := shr(96, to)
            }
            default {
                // Handle the default case if the function signature doesn't match any of the cases
            }
        }

        return (to, funcSig);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) external pure returns (bool) {
        return interfaceId == type(ISafeProtocolHooks).interfaceId;
    }
}

