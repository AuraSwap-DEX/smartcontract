// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./libraries/BoringERC20.sol";
import "./AuraToken.sol";
import "./SousChef.sol";

interface IRewarder {
    function onAuraReward(address user, uint256 newLpAmount) external;
    function pendingTokens(address user) external view returns (uint256 pending);
    function rewardToken() external view returns (IERC20);
}

contract MasterChef is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using BoringERC20 for IERC20;

    /// @notice Info of each user.
    /// `amount` LP token amount the user has provided.
    /// `rewardDebt` The amount of AURA entitled to the user.
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
    }

    /// @notice Info of each pool.
    /// `lpToken` Address of LP token contract.
    /// `allocPoint` The amount of allocation points assigned to the pool.
    ///     Also known as the amount of AURA to distribute per second.
    /// `lastRewardTimestamp` Last timestamp that AURAs distribution occurs.
    /// `accAuraPerShare` Accumulated AURAs per share.
    struct PoolInfo {
        IERC20 lpToken;
        uint256 allocPoint;
        uint256 lastRewardTimestamp;
        uint256 accAuraPerShare;
        IRewarder rewarder;
    }

    /// @notice The AURA TOKEN!
    AuraToken public aura;
    /// @notice The SOUS CHEF!
    SousChef public sous;
    /// @notice DEV address.
    address public devAddr;
    /// @notice AURA tokens created per second.
    uint256 public auraPerSec;
    /// @notice Limit aura per sec
    uint256 public auraPerSecLimit;

    /// @notice Info of each pool.
    PoolInfo[] public poolInfo;
    /// @notice Mapping to check which LP tokens have been added as pools.
    mapping(IERC20 => bool) public isPool;
    /// @notice Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    /// @notice Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint;
    /// @notice The timestamp when AURA mining starts.
    uint256 public startTimestamp;
    uint256 public constant ACC_AURA_PRECISION = 1e18;

    event Add(uint256 indexed pid, uint256 allocPoint, IERC20 indexed lpToken, IRewarder indexed rewarder);
    event Set(uint256 indexed pid, uint256 allocPoint, IRewarder indexed rewarder, bool overwrite);
    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event UpdatePool(uint256 indexed pid, uint256 lastRewardTimestamp, uint256 lpSupply, uint256 accAuraPerShare);
    event Harvest(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event SetDevAddress(address indexed oldAddress, address indexed newAddress);
    event UpdateEmissionRate(address indexed user, uint256 auraPerSec);

    constructor(
        AuraToken _aura,
        SousChef _sous,
        address _devAddr,
        uint256 _auraPerSec,
        uint256 _startTimestamp
    ) public {
        aura = _aura;
        sous = _sous;
        devAddr = _devAddr;
        auraPerSec = _auraPerSec;
        auraPerSecLimit = _auraPerSec;
        startTimestamp = _startTimestamp;
        totalAllocPoint = 0;
    }

    /// @notice Returns the number of MasterChef pools.
    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    /// @notice Add a new lp to the pool. Can only be called by the owner.
    /// DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    /// @param _allocPoint AP of the new pool.
    /// @param _lpToken Address of the LP ERC-20 token.
    /// @param _rewarder Address of the rewarder delegate.
    /// @param _withUpdate Whether call "massUpdatePools" operation.
    function add(
        uint256 _allocPoint,
        IERC20 _lpToken,
        IRewarder _rewarder,
        bool _withUpdate
    ) external onlyOwner {
        require(!isPool[_lpToken], "add: LP already added");
        // Sanity check to ensure _lpToken is an ERC20 token
        _lpToken.balanceOf(address(this));
        // Sanity check if we add a rewarder
        if (address(_rewarder) != address(0)) {
            _rewarder.onAuraReward(address(0), 0);
        }
        if (_withUpdate) {
            massUpdatePools();
        }

        uint256 lastRewardTimestamp = block.timestamp > startTimestamp ? block.timestamp : startTimestamp;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);

        poolInfo.push(
            PoolInfo({
                lpToken: _lpToken,
                allocPoint: _allocPoint,
                lastRewardTimestamp: lastRewardTimestamp,
                accAuraPerShare: 0,
                rewarder: _rewarder
            })
        );
        isPool[_lpToken] = true;
        emit Add(poolInfo.length.sub(1), _allocPoint, _lpToken, _rewarder);
    }

    /// @notice Update the given pool's AURA allocation point and `IRewarder` contract. Can only be called by the owner.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _allocPoint New AP of the pool.
    /// @param _rewarder Address of the rewarder delegate.
    /// @param overwrite True if _rewarder should be `set`. Otherwise `_rewarder` is ignored.
    /// @param _withUpdate Whether call "massUpdatePools" operation.
    function set(
        uint256 _pid,
        uint256 _allocPoint,
        IRewarder _rewarder,
        bool overwrite,
        bool _withUpdate
    ) external onlyOwner {
        // No matter _withUpdate is true or false, we need to execute updatePool once before set the pool parameters.
        updatePool(_pid);

        if (_withUpdate) {
            massUpdatePools();
        }

        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint;
        if (overwrite) {
            _rewarder.onAuraReward(address(0), 0); // sanity check
            poolInfo[_pid].rewarder = _rewarder;
        }
        emit Set(_pid, _allocPoint, overwrite ? _rewarder : poolInfo[_pid].rewarder, overwrite);
    }

    /// @notice View function to see pending AURA on frontend.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _user Address of user.
    /// @return pendingAura AURA reward for a given user.
    //          bonusTokenAddress The address of the bonus reward.
    //          bonusTokenSymbol The symbol of the bonus token.
    //          pendingBonusToken The amount of bonus rewards pending.
    function pendingTokens(uint256 _pid, address _user)
        external
        view
        returns (
            uint256 pendingAura,
            address bonusTokenAddress,
            string memory bonusTokenSymbol,
            uint256 pendingBonusToken
        )
    {
        PoolInfo memory pool = poolInfo[_pid];
        UserInfo memory user = userInfo[_pid][_user];
        uint256 accAuraPerShare = pool.accAuraPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (block.timestamp > pool.lastRewardTimestamp && lpSupply != 0) {
            uint256 timeElapsed = block.timestamp.sub(pool.lastRewardTimestamp);
            uint256 auraReward = timeElapsed.mul(auraPerSec).mul(pool.allocPoint).div(totalAllocPoint);
            accAuraPerShare = accAuraPerShare.add(auraReward.mul(ACC_AURA_PRECISION).div(lpSupply));
        }
        pendingAura = user.amount.mul(accAuraPerShare).div(ACC_AURA_PRECISION).sub(user.rewardDebt);

        // If it's a double reward farm, we return info about the bonus token
        if (address(pool.rewarder) != address(0)) {
            bonusTokenAddress = address(pool.rewarder.rewardToken());
            bonusTokenSymbol = IERC20(pool.rewarder.rewardToken()).safeSymbol();
            pendingBonusToken = pool.rewarder.pendingTokens(_user);
        }
    }

    /// @notice Update aura reward for all the active pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            PoolInfo memory pool = poolInfo[pid];
            if (pool.allocPoint != 0) {
                updatePool(pid);
            }
        }
    }

    /// @notice Update reward variables of the given pool.
    /// @param _pid The index of the pool. See `poolInfo`.
    function updatePool(uint256 _pid) public {
        PoolInfo memory pool = poolInfo[_pid];
        if (block.timestamp > pool.lastRewardTimestamp) {
            uint256 lpSupply = pool.lpToken.balanceOf(address(this));
            // gas opt and prevent div by 0
            if (lpSupply > 0 && totalAllocPoint > 0) {
                uint256 timeElapsed = block.timestamp.sub(pool.lastRewardTimestamp);
                uint256 auraReward = timeElapsed.mul(auraPerSec).mul(pool.allocPoint).div(totalAllocPoint);
                aura.mint(devAddr, auraReward.div(8));
                aura.mint(address(sous), auraReward);
                pool.accAuraPerShare = pool.accAuraPerShare.add(auraReward.mul(ACC_AURA_PRECISION).div(lpSupply));
            }
            pool.lastRewardTimestamp = block.timestamp;
            poolInfo[_pid] = pool;
            emit UpdatePool(_pid, pool.lastRewardTimestamp, lpSupply, pool.accAuraPerShare);
        }
    }

    /// @notice Deposit LP tokens to MasterChef for Aura allocation.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _amount LP token amount to deposit.
    function deposit(uint256 _pid, uint256 _amount) external nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        updatePool(_pid);

        if (user.amount > 0) {
            // Harvest AURA
            uint256 pending = user.amount.mul(pool.accAuraPerShare).div(ACC_AURA_PRECISION).sub(user.rewardDebt);
            if(pending > 0) {
                safeAuraTransfer(msg.sender, pending);
                emit Harvest(msg.sender, _pid, pending);
            }            
        }
        if (_amount > 0) {
            pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
            user.amount = user.amount.add(_amount);
        }
        user.rewardDebt = user.amount.mul(pool.accAuraPerShare).div(ACC_AURA_PRECISION);

        IRewarder rewarder = pool.rewarder;
        if (address(rewarder) != address(0)) {
            rewarder.onAuraReward(msg.sender, user.amount);
        }
        emit Deposit(msg.sender, _pid, _amount);
    }

    /// @notice Withdraw LP tokens from MasterChef.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _amount LP token amount to withdraw.
    function withdraw(uint256 _pid, uint256 _amount) external nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: Insufficient");

        updatePool(_pid);

        // Harvest AURA
        uint256 pending = user.amount.mul(pool.accAuraPerShare).div(ACC_AURA_PRECISION).sub(user.rewardDebt);
        if(pending > 0) {
            safeAuraTransfer(msg.sender, pending);
            emit Harvest(msg.sender, _pid, pending);
        }
        if(_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(msg.sender), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accAuraPerShare).div(ACC_AURA_PRECISION);

        IRewarder rewarder = pool.rewarder;
        if (address(rewarder) != address(0)) {
            rewarder.onAuraReward(msg.sender, user.amount);
        }
        emit Withdraw(msg.sender, _pid, _amount);
    }

    /// @notice Withdraw without caring about rewards. EMERGENCY ONLY.
    /// @param _pid The index of the pool. See `poolInfo`.
    function emergencyWithdraw(uint256 _pid) external nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;

        IRewarder rewarder = pool.rewarder;
        if (address(rewarder) != address(0)) {
            rewarder.onAuraReward(msg.sender, 0);
        }

        // Note: transfer can fail or succeed if `amount` is zero.
        pool.lpToken.safeTransfer(address(msg.sender), amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);

    }

    /// @notice Safe aura transfer function, just in case if rounding error causes pool to not have enough AURAs.
    function safeAuraTransfer(address _to, uint256 _amount) internal {
        sous.safeAuraTransfer(_to, _amount);
    }

    /// @notice Update dev address by the previous dev.
    function dev(address _devAddr) external {
        require(msg.sender == devAddr, "dev: wut?");
        devAddr = _devAddr;
        emit SetDevAddress(msg.sender, _devAddr);
    }

    /// @notice Update aura per second
    function updateEmissionRate(uint256 _auraPerSec) external onlyOwner {
        require(_auraPerSec < auraPerSecLimit, "updateEmissionRate: cannot exceed auraPerSecLimit");
        massUpdatePools();
        auraPerSec = _auraPerSec;
        emit UpdateEmissionRate(msg.sender, _auraPerSec);
    }
}
