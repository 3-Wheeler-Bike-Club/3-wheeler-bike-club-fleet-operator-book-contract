// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {FleetOperatorBook} from "../src/FleetOperatorBook.sol";

contract FleetOperatorBookScript is Script {
    FleetOperatorBook public fleetOperatorBook;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        fleetOperatorBook = new FleetOperatorBook();

        vm.stopBroadcast();
    }
}
