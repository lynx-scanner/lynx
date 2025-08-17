// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * SimpleToken.sol
 * 
 * A simple token contract with vulnerabilities for testing.
 * Uses older Solidity version to demonstrate overflow issues.
 */

contract SimpleToken {
    string public name = "Simple Token";
    string public symbol = "SIMPLE";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    address public owner;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(uint256 _initialSupply) {
        owner = msg.sender;
        totalSupply = _initialSupply * 10 ** decimals;
        balanceOf[msg.sender] = totalSupply;
    }
    
    // VULNERABILITY: tx.origin for authorization
    function mint(address to, uint256 amount) external {
        require(tx.origin == owner, "Only owner can mint");
        
        // VULNERABILITY: Integer overflow possible in older Solidity
        totalSupply += amount;
        balanceOf[to] += amount;
        
        emit Transfer(address(0), to, amount);
    }
    
    // VULNERABILITY: No zero address check
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        
        // VULNERABILITY: Integer overflow/underflow possible
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        
        emit Transfer(msg.sender, to, value);
        return true;
    }
    
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");
        
        // VULNERABILITY: Integer overflow/underflow possible
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        
        emit Transfer(from, to, value);
        return true;
    }
    
    // VULNERABILITY: Weak randomness for token distribution
    function randomAirdrop() external {
        uint256 randomAmount = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        ))) % 1000;
        
        // VULNERABILITY: Integer overflow possible
        balanceOf[msg.sender] += randomAmount;
        totalSupply += randomAmount;
        
        emit Transfer(address(0), msg.sender, randomAmount);
    }
    
    // VULNERABILITY: Unchecked external call
    function notifyContract(address target, bytes calldata data) external {
        require(msg.sender == owner, "Only owner");
        target.call(data);
    }
    
    // VULNERABILITY: Unprotected selfdestruct
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABILITY: DoS via gas limit
    address[] public holders;
    
    function distributeTokens(uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        
        // Unbounded loop - can run out of gas
        for (uint256 i = 0; i < holders.length; i++) {
            balanceOf[holders[i]] += amount;
        }
    }
    
    function addHolder(address holder) external {
        holders.push(holder);
    }
    
    // VULNERABILITY: Timestamp dependence
    function timeBasedMint() external {
        require(block.timestamp > 1640995200, "Minting not started");
        
        if (block.timestamp % 2 == 0) {
            balanceOf[msg.sender] += 100;
            totalSupply += 100;
        }
    }
}
