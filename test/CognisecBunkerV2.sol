// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CognisecBunker, CognisecBunkerFactory} from "../src/CognisecBunkerUpgradeable.sol";

contract CognisecBunkerV2 is CognisecBunker {
    function implementationVersion() external pure returns (uint256) {
        return 2;
    }
}

contract CognisecBunkerFactoryV2 is CognisecBunkerFactory {
    function implementationVersion() external pure returns (uint256) {
        return 2;
    }
}

contract MockCognisecToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function decimals() external pure returns (uint8) {
        return 18;
    }

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        require(balanceOf[sender] >= amount, "balance");
        uint256 permitted = allowance[sender][msg.sender];
        require(permitted >= amount, "allowance");
        allowance[sender][msg.sender] = permitted - amount;
        balanceOf[sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

contract MockKyberRouter {
    function swap(
        address assetIn,
        address assetOut,
        uint256 amountIn,
        uint256 amountOut
    ) external payable {
        if (assetIn == address(0)) {
            require(msg.value == amountIn, "native input");
        } else {
            require(msg.value == 0, "unexpected value");
            MockCognisecToken(assetIn).transferFrom(msg.sender, address(this), amountIn);
        }
        MockCognisecToken(assetOut).mint(msg.sender, amountOut);
    }
}
