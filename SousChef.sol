pragma solidity 0.6.12;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./AuraToken.sol";

contract SousChef is Ownable {
    // The AURA TOKEN
    AuraToken public aura;

    constructor(
        AuraToken _aura
    ) public {
        aura = _aura;
    }

    // Safe aura transfer function, just in case if rounding error causes pool to not have enough AURAs.
    function safeAuraTransfer(address _to, uint256 _amount) public onlyOwner {
        uint256 auraBal = aura.balanceOf(address(this));
        if (_amount > auraBal) {
            aura.transfer(_to, auraBal);
        } else {
            aura.transfer(_to, _amount);
        }
    }
}