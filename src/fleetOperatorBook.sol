// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @dev Interface imports
import { IFleetOrderYield } from "./interfaces/IFleetOrderYield.sol";

/// @dev OpenZeppelin utils imports
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @dev OpenZeppelin access imports
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @dev OpenZeppelin nft imports
import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";


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

contract FleetOperatorBook is ERC721, AccessControl, ReentrancyGuard{
    using SafeERC20 for IERC20;


    /// @notice Role definitions
    bytes32 public constant SUPER_ADMIN_ROLE = keccak256("SUPER_ADMIN_ROLE");
    //bytes32 public constant FLEET_ORDER_YIELD_ROLE = keccak256("FLEET_ORDER_YIELD_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");
    bytes32 public constant WITHDRAWAL_ROLE = keccak256("WITHDRAWAL_ROLE");
    

    /// @notice The fleet order yield contract.
    IFleetOrderYield public fleetOrderYieldContract;
    /// @notice The yield token for the fleet order yield contract.
    IERC20 public yieldToken;


    /// @notice The total number of fleet operators.
    uint256 public totalFleetOperators;
    /// @notice The fleet operator reservation fee for the fleet order yield contract.
    uint256 public fleetOperatorReservationFee;
    /// @notice The fleet management service fee wallet for the fleet order yield contract.
    address public fleetOperatorReservationFeeWallet;
    /// @notice The number of next fleet operator reservation to serve.
    uint256 public fleetOperatorReservationToServe;
        

    /// @notice Whether an operator is compliant.
    mapping(address => bool) public isOperatorCompliant;
    /// @notice The fleet operator reservation token id.
    mapping(address => uint256) public fleetOperatorReservationNumber;


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
    /// @notice Thrown when the operator is already queued in reservation waitlist
    error AlreadyQueued();
    /// @notice Thrown when the fleet operator is not available
    error FleetOperatorNotAvailable();
    /// @notice Thrown when the reservation is attempted to be transferred
    error ReservationNotTransferable();



    constructor() 
    ERC721("FleetOperatorBook", "FOB") 
    AccessControl() 
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SUPER_ADMIN_ROLE, msg.sender);
    }


    /// @notice Override supportsInterface to handle multiple inheritance
    /// @param interfaceId The interface ID to check
    /// @return bool True if the interface is supported
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }


    /// @notice Set the yield token for the fleet order yield contract.
    /// @param _yieldToken The address of the yield token.
    function setYieldToken(address _yieldToken) external onlyRole(SUPER_ADMIN_ROLE) {
        if (_yieldToken == address(0)) revert InvalidAddress();
        if (_yieldToken == address(yieldToken)) revert TokenAlreadySet();

        yieldToken = IERC20(_yieldToken);
    }


    /// @notice Set the fleet order yield contract.
    /// @param _fleetOrderYieldContract The address of the fleet order yield contract.
    function setFleetOrderYieldContract(address _fleetOrderYieldContract) external onlyRole(SUPER_ADMIN_ROLE) {
        if (_fleetOrderYieldContract == address(0)) revert InvalidAddress();
        fleetOrderYieldContract = IFleetOrderYield(_fleetOrderYieldContract);
    }

    
    /// @notice Set the fleet operator reservation fee for the fleet order yield contract.
    /// @param _fleetOperatorReservationFee The amount of the ERC20 to pay in USD with 6 decimals
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
        uint256 decimals = IERC20Metadata(address(yieldToken)).decimals();
        
        if (yieldToken.balanceOf(msg.sender) < ((amount * (10 ** decimals)) / 1e6)) revert NotEnoughTokens();
        yieldToken.safeTransferFrom(msg.sender, address(this), ((amount * (10 ** decimals)) / 1e6));
    }


    /// @notice Pay the fleet operator reservation fee.
    /// @param operator The address of the operator.
    function payFleetOperatorReservationFee(address operator) external nonReentrant {
        if (operator == address(0)) revert InvalidAddress();
        if (!isOperatorCompliant[operator]) revert NotCompliant();

        //revert if operator not available
        bool isFleetOperatorAvailable = fleetOrderYieldContract.isFleetOperatorAvailable(operator);
        if (!isFleetOperatorAvailable) revert FleetOperatorNotAvailable();


        //revert if already in queue
        if (fleetOperatorReservationNumber[operator] != 0) revert AlreadyQueued();
        
        // pay erc20 from drivers
        payERC20( fleetOperatorReservationFee );

        //mint reservation token
        uint256 tokenId = totalFleetOperators++;
        fleetOperatorReservationNumber[operator] = tokenId;
        _safeMint(operator, tokenId);

        emit FleetOperatorReserved(operator, fleetOperatorReservationFee);
    }


    /// @notice Assign the next fleet operator reservation.
    /// @return The address of the next fleet operator reservation.
    function assignNextFleetOperatorReservation() external nonReentrant onlyRole(SUPER_ADMIN_ROLE) returns (address) {
        uint256 currentFleetOperatorReservation = fleetOperatorReservationToServe;
        address currentFleetOperator = ownerOf(currentFleetOperatorReservation);
        fleetOperatorReservationToServe++;
        fleetOperatorReservationNumber[currentFleetOperator] = 0;
        _burn(currentFleetOperatorReservation);
        return currentFleetOperator;
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


    /// @notice Override the _update function to block transfers.
    /// @param to The address to transfer the token to.
    /// @param tokenId The token id to transfer.
    /// @param auth The address to authorize the transfer.
    /// @return The address of the new owner.
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        address from = _ownerOf(tokenId);

        // Block transfers: only allow mint (from == 0) or burn (to == 0)
        if (from != address(0) && to != address(0)) {
            revert ReservationNotTransferable();
        }

        return super._update(to, tokenId, auth);
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
