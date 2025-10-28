// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @dev OpenZeppelin utils imports
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @dev OpenZeppelin access imports
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title 3wb.club fleet operator book V1.0
/// @notice Manages fleet operator serserve, waitlist & for fractional and full investments in 3-wheelers
/// @author geeloko.eth
/// 
/// @dev Role-based Access Control System:
/// - DEFAULT_ADMIN_ROLE: Can grant/revoke all other roles, highest privilege
/// - SUPER_ADMIN_ROLE: Can pause/unpause, set prices, max orders, add/remove ERC20s, update fleet status
/// - COMPLIANCE_ROLE: Can set compliance status for users
/// - WITHDRAWAL_ROLE: Can withdraw sales from the contract
/// 
/// @dev Security Benefits:
/// - Reduces risk of compromising the deployer wallet
/// - Allows delegation of specific functions to different admin addresses
/// - Provides granular control over different aspects of the contract
/// - Enables multi-signature or DAO governance for critical functions

contract FleetOperatorBook is AccessControl, ReentrancyGuard{
    using SafeERC20 for IERC20;

    /// @notice Role definitions
    bytes32 public constant SUPER_ADMIN_ROLE = keccak256("SUPER_ADMIN_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");
    bytes32 public constant WITHDRAWAL_ROLE = keccak256("WITHDRAWAL_ROLE");


    /// @notice The yield token for the fleet order yield contract.
    IERC20 public yieldToken;
    /// @notice The fleet operator reservation fee for the fleet order yield contract.
    uint256 public fleetOperatorReservationFee;
    /// @notice The fleet management service fee wallet for the fleet order yield contract.
    address public fleetOperatorReservationFeeWallet;

    /// @notice The fleet operator reservation waitlist.
    address[] private fleetOperatorReservationWaitlist;
    


    /// @notice Whether an operator is compliant.
    mapping(address => bool) public isOperatorCompliant;

    
    /// @notice tracking fleet reservation index for each operator
    mapping(address =>  uint256) private fleetOperatorReservationWaitlistIndex;


    /// @notice Event emitted when the fleet operator reservation fee is paid
    event FleetOperatorReserved(address indexed operator, uint256 amount);  
    /// @notice Event emitted when the fleet operator reservation fee is withdrawn
    event FleetOperatorReservationFeeWithdrawn(address indexed token, address indexed to, uint256 amount);


    /// @notice Thrown when the id is Zero
    error InvalidId();
    /// @notice Thrown when the id does not exist
    error IdDoesNotExist();
    /// @notice Thrown when the token address is invalid
    error InvalidAddress();
    /// @notice Thrown when the amount is invalid
    error InvalidAmount();
    /// @notice Thrown when the token address is already set
    error TokenAlreadySet();
    /// @notice Thrown when the user does not have enough tokens
    error NotEnoughTokens();
    /// @notice Thrown when the native token is not accepted
    error NoNativeTokenAccepted();
    /// @notice Thrown when the operator is not compliant
    error NotCompliant();
    /// @notice Thrown when the operator is already compliant
    error AlreadyCompliant();



    constructor() AccessControl() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SUPER_ADMIN_ROLE, msg.sender);
    }


    /// @notice Override supportsInterface to handle multiple inheritance
    /// @param interfaceId The interface ID to check
    /// @return bool True if the interface is supported
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControl) returns (bool) {
        return AccessControl.supportsInterface(interfaceId);
    }


    /// @notice Set the yield token for the fleet order yield contract.
    /// @param _yieldToken The address of the yield token.
    function setYieldToken(address _yieldToken) external onlyRole(SUPER_ADMIN_ROLE) {
        if (_yieldToken == address(0)) revert InvalidAddress();
        if (_yieldToken == address(yieldToken)) revert TokenAlreadySet();

        yieldToken = IERC20(_yieldToken);
    }


    
    /// @notice Set the fleet operator reservation fee for the fleet order yield contract.
    /// @param _fleetOperatorReservationFee The fleet operator reservation fee to set.
    function setFleetOperatorReservationFee(uint256 _fleetOperatorReservationFee) external onlyRole(SUPER_ADMIN_ROLE) {
        fleetOperatorReservationFee = _fleetOperatorReservationFee;
    }

        /// @notice Set the compliance.
    /// @param operators The addresses to set as compliant.
    function setOperatorCompliance(address[] calldata operators) external onlyRole(COMPLIANCE_ROLE) {
        if (operators.length == 0) revert InvalidAmount();
        for (uint256 i = 0; i < operators.length; i++) {
                if (isOperatorCompliant[operators[i]]) revert AlreadyCompliant();
            }

        for (uint256 i = 0; i < operators.length; i++) {
            isOperatorCompliant[operators[i]] = true;
        }
    }


    /// @notice Pay fee in ERC20.
    /// @param amount The amount of the ERC20 to pay in USD with 6 decimals.
    function payERC20(uint256 amount) internal {
        //IERC20 tokenContract = IERC20(erc20Contract);
        uint256 decimals = IERC20Metadata(address(yieldToken)).decimals();
        
        if (yieldToken.balanceOf(msg.sender) < ((amount * (10 ** decimals)) / 1e6)) revert NotEnoughTokens();
        yieldToken.safeTransferFrom(msg.sender, address(this), ((amount * (10 ** decimals)) / 1e6));
    }


    function payFleetOperatorReservationFee(address operator) external nonReentrant {
        if (operator == address(0)) revert InvalidAddress();
        if (!isOperatorCompliant[operator]) revert NotCompliant();
        // pay erc20 from drivers
        payERC20( fleetOperatorReservationFee );
        addFleetOperatorReservation(operator);
        emit FleetOperatorReserved(operator, fleetOperatorReservationFee);
        
    }

    /// @notice Add a fleet owner.
    /// @param operator The address of the operator.
    function addFleetOperatorReservation(address operator) internal {
        address[] storage operators = fleetOperatorReservationWaitlist;
        operators.push(operator);
        fleetOperatorReservationWaitlistIndex[operator] = operators.length - 1;
    }


    /// @notice Remove a fleet owner.
    function removeFleetOperatorReservation() internal {
        // Get the index of the orderId in the owner's fleetOwned array.
        uint256 indexToRemove = 0;
        uint256 lastIndex = fleetOperatorReservationWaitlist.length - 1;
        address operatorToRemove = fleetOperatorReservationWaitlist[indexToRemove];

        // If the order being removed is not the last one, swap it with the last element.
        if (indexToRemove != lastIndex) {
            address lastOperator = fleetOperatorReservationWaitlist[lastIndex];
            fleetOperatorReservationWaitlist[indexToRemove] = lastOperator;
            // Update the index mapping for the swapped order.
            fleetOperatorReservationWaitlistIndex[lastOperator] = indexToRemove;
        }
        
        // Remove the last element and delete the mapping entry for the removed order.
        fleetOperatorReservationWaitlist.pop();
        delete fleetOperatorReservationWaitlistIndex[operatorToRemove];
    }


    function getNextFleetOperatorReservation() external nonReentrant onlyRole(SUPER_ADMIN_ROLE) returns (address) {
        address nextOperator = fleetOperatorReservationWaitlist[0];
        removeFleetOperatorReservation();
        return nextOperator;
    }



    /// @notice Withdraw sales from fleet order book.
    /// @param token The address of the ERC20 contract.
    /// @param to The address to send the sales to.
    function withdrawFleetOperatorReservationFee(address token, address to) external nonReentrant onlyRole(WITHDRAWAL_ROLE){
        if (token == address(0)) revert InvalidAddress();
        IERC20 tokenContract = IERC20(token);
        uint256 amount = tokenContract.balanceOf(address(this));
        if (amount == 0) revert NotEnoughTokens();
        tokenContract.safeTransfer(to, amount);
        emit FleetOperatorReservationFeeWithdrawn(token, to, amount);
    }

    receive() external payable { revert NoNativeTokenAccepted(); }
    fallback() external payable { revert NoNativeTokenAccepted(); }
    
    // =================================================== ADMIN MANAGEMENT ====================================================

    /// @notice Grant compliance role to an address
    /// @param account The address to grant the compliance role to
    function grantComplianceRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(COMPLIANCE_ROLE, account);
    }

    /// @notice Revoke compliance role from an address
    /// @param account The address to revoke the compliance role from
    function revokeComplianceRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(COMPLIANCE_ROLE, account);
    }

    /// @notice Grant withdrawal role to an address
    /// @param account The address to grant the withdrawal role to
    function grantWithdrawalRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(WITHDRAWAL_ROLE, account);
    }

    /// @notice Revoke withdrawal role from an address
    /// @param account The address to revoke the withdrawal role from
    function revokeWithdrawalRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(WITHDRAWAL_ROLE, account);
    }

    /// @notice Grant super admin role to an address
    /// @param account The address to grant the super admin role to
    function grantSuperAdminRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(SUPER_ADMIN_ROLE, account);
    }

    /// @notice Revoke super admin role from an address
    /// @param account The address to revoke the super admin role from
    function revokeSuperAdminRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(SUPER_ADMIN_ROLE, account);
    }

    /// @notice Check if an address has compliance role
    /// @param account The address to check
    /// @return bool True if the address has compliance role
    function isCompliance(address account) external view returns (bool) {
        return hasRole(COMPLIANCE_ROLE, account);
    }

    /// @notice Check if an address has withdrawal role
    /// @param account The address to check
    /// @return bool True if the address has withdrawal role
    function isWithdrawal(address account) external view returns (bool) {
        return hasRole(WITHDRAWAL_ROLE, account);
    }

    /// @notice Check if an address has super admin role
    /// @param account The address to check
    /// @return bool True if the address has super admin role
    function isSuperAdmin(address account) external view returns (bool) {
        return hasRole(SUPER_ADMIN_ROLE, account);
    }
}
