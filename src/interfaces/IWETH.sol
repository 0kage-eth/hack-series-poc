//SPDX-License-Identifier:UNLICENSED
pragma solidity 0.8.10;
interface IWETH {
    function deposit() external payable;

    function withdraw(uint256) external payable;
    
    function transfer(address,uint) external returns (bool);
    function balanceOf(address) external returns(uint256);

    function totalSupply() external view returns (uint);
}