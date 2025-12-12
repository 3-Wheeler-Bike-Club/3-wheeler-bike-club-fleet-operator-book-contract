// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title 3wb.club fleet order yield interface V1.0
/// @notice interface for yields for fractional and full investments in 3-wheelers
/// @author Geeloko

interface IFleetOrderYield {
    /// @notice Check if a fleet operator is available to be assigned a new fleet.
    /// @param operator The address of the operator to check.
    /// @return bool True if the operator is available to be assigned a new fleet.
    function isFleetOperatorAvailable(address operator) external view returns (bool);


}
