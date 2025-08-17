// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * SafeContract.sol
 * 
 * This contract demonstrates secure coding practices.
 * Shows how to properly implement security measures.
 */

import "./SafeMath.sol";

contract SafeContract {
    using SafeMath for uint256;
    
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;
    uint256 public constant MAX_USERS = 1000;
    address[] public users;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    modifier validAddress(address _addr) {
        require(_addr != address(0), "Invalid address: zero address");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] = balances[msg.sender].add(msg.value);
        emit Deposit(msg.sender, msg.value);
    }
    
    // SAFE: Proper reentrancy protection with checks-effects-interactions
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be greater than 0");
        
        // Effects: Update state first
        balances[msg.sender] = balances[msg.sender].sub(amount);
        
        // Interactions: External calls last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, amount);
    }
    
    // SAFE: Proper address validation
    function transfer(address to, uint256 amount) external validAddress(to) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be greater than 0");
        require(to != msg.sender, "Cannot transfer to yourself");
        
        balances[msg.sender] = balances[msg.sender].sub(amount);
        balances[to] = balances[to].add(amount);
        
        emit Transfer(msg.sender, to, amount);
    }
    
    // SAFE: Better randomness (still not perfect, use Chainlink VRF in production)
    function secureRandomness(uint256 nonce) external view returns (uint256) {
        // Better than block properties alone, but still use Chainlink VRF for production
        return uint256(keccak256(abi.encodePacked(
            blockhash(block.number - 1),
            msg.sender,
            address(this),
            nonce
        )));
    }
    
    // SAFE: Checked low-level call with return value handling
    function checkedCall(address target, bytes calldata data) 
        external 
        onlyOwner 
        validAddress(target) 
        returns (bool success, bytes memory returnData) 
    {
        // Checked low-level call with return value handling
        (success, returnData) = target.call(data);
        
        if (!success) {
            // Handle failure appropriately
            revert("External call failed");
        }
        
        return (success, returnData);
    }
    
    // SAFE: Protected selfdestruct with proper access control
    function destroy() external onlyOwner {
        // Only owner can destroy, sends funds to owner
        selfdestruct(payable(owner));
    }
    
    // SAFE: Timestamp with tolerance
    uint256 public constant TIME_TOLERANCE = 300; // 5 minutes
    
    function timeBasedActionSafe(uint256 targetTime) external {
        // Allow some tolerance for timestamp manipulation
        require(
            block.timestamp >= targetTime.sub(TIME_TOLERANCE), 
            "Too early"
        );
        require(
            block.timestamp <= targetTime.add(TIME_TOLERANCE), 
            "Too late"
        );
        
        balances[msg.sender] = balances[msg.sender].add(100);
    }
    
    // SAFE: DoS protection with pagination
    function distributeRewardsSafe(uint256 startIndex, uint256 endIndex) external onlyOwner {
        require(startIndex < endIndex, "Invalid range");
        require(endIndex <= users.length, "End index out of bounds");
        require(endIndex.sub(startIndex) <= 50, "Batch size too large"); // Limit batch size
        
        for (uint256 i = startIndex; i < endIndex; i++) {
            balances[users[i]] = balances[users[i]].add(10);
        }
    }
    
    // SAFE: Proper ownership transfer with zero address check
    function transferOwnership(address newOwner) external onlyOwner validAddress(newOwner) {
        require(newOwner != owner, "New owner must be different");
        
        address previousOwner = owner;
        owner = newOwner;
        
        emit OwnershipTransferred(previousOwner, newOwner);
    }
    
    // SAFE: Add user with limits and validation
    function addUser(address user) external onlyOwner validAddress(user) {
        require(users.length < MAX_USERS, "Maximum users reached");
        
        // Check if user already exists
        for (uint256 i = 0; i < users.length; i++) {
            require(users[i] != user, "User already exists");
        }
        
        users.push(user);
    }
    
    // SAFE: Batch operations with limits
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        require(recipients.length <= 20, "Too many recipients"); // Limit batch size
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount = totalAmount.add(amounts[i]);
        }
        
        require(balances[msg.sender] >= totalAmount, "Insufficient balance for batch");
        
        balances[msg.sender] = balances[msg.sender].sub(totalAmount);
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid recipient");
            balances[recipients[i]] = balances[recipients[i]].add(amounts[i]);
            emit Transfer(msg.sender, recipients[i], amounts[i]);
        }
    }
    
    // View functions
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    function getUserCount() external view returns (uint256) {
        return users.length;
    }
    
    function getUsersInRange(uint256 startIndex, uint256 endIndex) 
        external 
        view 
        returns (address[] memory) 
    {
        require(startIndex < endIndex, "Invalid range");
        require(endIndex <= users.length, "End index out of bounds");
        
        address[] memory result = new address[](endIndex.sub(startIndex));
        for (uint256 i = startIndex; i < endIndex; i++) {
            result[i.sub(startIndex)] = users[i];
        }
        
        return result;
    }
    
    // Emergency functions
    function emergencyPause() external onlyOwner {
        // Emergency functions should use msg.sender, not tx.origin
        locked = true;
    }
    
    function unpause() external onlyOwner {
        locked = false;
    }
    
    function emergencyWithdraw() external onlyOwner {
        // Emergency withdrawal for contract owner
        require(address(this).balance > 0, "No funds to withdraw");
        
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Emergency withdrawal failed");
    }
}
