// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");

        return a - b;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, "SafeMath: division by zero");

        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return a / b;
    }
}

/**
 * @title String
 * @dev This integrates the basic functions.
 */
library String {
    /**
     * @dev determine if strings are equal
     * @param _str1 strings
     * @param _str2 strings
     * @return bool
     */
    function compareStr(string memory _str1, string memory _str2)
        internal
        pure
        returns(bool)
    {
        return keccak256(abi.encodePacked(_str1)) == keccak256(abi.encodePacked(_str2));
    }
}

/**
 * @title Rand
 * @dev Rand operations.
 */
contract Rand {

    mapping(uint8 => uint) internal rNGMapping;

    /**
     * @dev the content of contract is Beginning
     */
	constructor () public
    {
        //init
        rNGMapping[1] = _rand() % block.difficulty;
    }

    /**
     * @dev Gets the get Random
     * @param _length Random _length
     * @return random Random
     */
    function rand(uint _length)
        internal
        returns(uint random)
    {
        random = _rand();
        rNGMapping[1] = random;
        return random % _length;
    }

    /**
     * @dev Gets the get Random
     * @return Random
     */
    function _rand()
        private
        returns(uint)
    {
        return uint(keccak256(abi.encodePacked(
            block.difficulty, block.gaslimit, now, tx.gasprice , tx.origin,
            ++rNGMapping[0], rNGMapping[1]
        )));
    }
}

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * This test is non-exhaustive, and there may be false-negatives: during the
     * execution of a contract's constructor, its address will be reported as
     * not containing a contract.
     *
     * IMPORTANT: It is unsafe to assume that an address for which this
     * function returns false is an externally-owned account (EOA) and not a
     * contract.
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies in extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != 0x0 && codehash != accountHash);
    }

    /**
     * @dev Converts an `address` into `address payable`. Note that this is
     * simply a type cast: the actual underlying value is not changed.
     *
     * _Available since v2.4.0._
     */
    function toPayable(address account) internal pure returns (address payable) {
        return address(uint160(account));
    }
}

/**
 * @title DB interface
 * @dev This Provide database support services interface
 */
interface IDB {
    /**
     * @dev Create store user information
     * @param addr user addr
     * @param code user invite Code
     * @param rCode recommend code
     */
    function registerUser(address addr, string calldata code, string calldata rCode) external;
    /**
     * @dev Set store user information
     * @param addr user addr
     * @param status user status
     */
    function setUser(address addr, uint8 status) external;
    /**
     * @dev Set store user information [level]
     * @param addr user addr
     * @param level user level
     * @param levelStatus user level status
     */
    function setUserLevel(address addr, uint8 level, uint8 levelStatus) external;
    /**
     * @dev determine if user invite code is use (db)
     * @param code user invite Code
     * @return bool
     */
    function isUsedCode(string calldata code) external view returns (bool);
    /**
     * @dev get the user address of the corresponding user invite code (db)
     * Authorization Required
     * @param code user invite Code
     * @return address
     */
    function getCodeMapping(string calldata code) external view returns (address);
    /**
     * @dev get the user address of the corresponding user id (db)
     * Authorization Required
     * @param uid user id
     * @return address
     */
    function getIndexMapping(uint uid) external view returns (address);
    /**
     * @dev get the user address of the corresponding User info (db)
     * @param addr user address
     * @return info info[id,status,level,levelStatus]
     * @return code code
     * @return rCode rCode
     */
    function getUserInfo(address addr) external view returns (uint[4] memory info, string memory code, string memory rCode);
    /**
     * @dev get the current latest ID (db)
     * Authorization Required
     * @return current uid
     */
    function getCurrentUserID() external view returns (uint);
    /**
     * @dev get the rCodeMapping array length of the corresponding recommend Code (db)
     * Authorization Required
     * @param rCode recommend Code
     * @return rCodeMapping array length
     */
    function getRCodeMappingLength(string calldata rCode) external view returns (uint);
    /**
     * @dev get the user invite code of the recommend Code [rCodeMapping] based on the index (db)
     * Authorization Required
     * @param rCode recommend Code
     * @param index the index of [rCodeMapping]
     * @return user invite code
     */
    function getRCodeMapping(string calldata rCode, uint index) external view returns (string memory);
    /**
     * @dev get the user offspring
     * Authorization Required
     * @param rCode recommend Code
     */
    function getRCodeOffspring(string calldata rCode) external view returns (string[] memory);
}

/**
 * @title DBUtilli
 * @dev This Provide database support services (db)
 */
contract DBUtilli {

    //include other contract
    IDB private db;

    /**
     * @dev DBUtilli is Beginning
     * @param _dbAddr db contract addr
     */
    constructor(address _dbAddr)
        public
    {
        db = IDB(_dbAddr);
    }

    /**
     * @dev Create store user information (db)
     * @param addr user address
     * @param code user invite Code
     * @param rCode recommend code
     */
    function _registerUser(address addr, string memory code, string memory rCode)
        internal
    {
        db.registerUser(addr, code, rCode);
	}

    /**
     * @dev Set store user information
     * @param addr user addr
     * @param status user status
     */
    function _setUser(address addr, uint8 status)
        internal
    {
		db.setUser(addr, status);
	}

    /**
     * @dev Set store user information [level]
     * @param addr user addr
     * @param level user level
     * @param levelStatus user level status
     */
    function _setUserLevel(address addr, uint8 level, uint8 levelStatus)
        internal
    {
        db.setUserLevel(addr, level, levelStatus);
	}

    /**
     * @dev determine if user invite code is use (db)
     * @param code user invite Code
     * @return isUser bool
     */
    function _isUsedCode(string memory code)
        internal
        view
        returns (bool)
    {
		return db.isUsedCode(code);
	}

    /**
     * @dev get the user address of the corresponding user invite code (db)
     * Authorization Required
     * @param code user invite Code
     * @return addr address
     */
    function _getCodeMapping(string memory code)
        internal
        view
        returns (address)
    {
        return db.getCodeMapping(code);
	}

    /**
     * @dev get the user address of the corresponding user id (db)
     * Authorization Required
     * @param uid user id
     * @return addr address
     */
    function _getIndexMapping(uint uid)
        internal
        view
        returns (address)
    {
		return db.getIndexMapping(uid);
	}

    /**
     * @dev get the user address of the corresponding User info (db)
     * @param addr user address
     * @return info info[id,status,level,levelStatus]
     * @return code code
     * @return rCode rCode
     */
    function _getUserInfo(address addr)
        internal
        view
        returns (uint[4] memory info, string memory code, string memory rCode)
    {
		return db.getUserInfo(addr);
	}

    /**
     * @dev get the current latest ID (db)
     * Authorization Required
     * @return uid current uid
     */
    function _getCurrentUserID()
        internal
        view
        returns (uint)
    {
		return db.getCurrentUserID();
	}

    /**
     * @dev get the rCodeMapping array length of the corresponding recommend Code (db)
     * Authorization Required
     * @param rCode recommend Code
     * @return length rCodeMapping array length
     */
    function _getRCodeMappingLength(string memory rCode)
        internal
        view
        returns (uint)
    {
		return db.getRCodeMappingLength(rCode);
	}

    /**
     * @dev get the user invite code of the recommend Code [rCodeMapping] based on the index (db)
     * Authorization Required
     * @param rCode recommend Code
     * @param index the index of [rCodeMapping]
     * @return code user invite code
     */
    function _getRCodeMapping(string memory rCode, uint index)
        internal
        view
        returns (string memory)
    {
		return db.getRCodeMapping(rCode, index);
	}

    /**
     * @dev get the user offspring
     * Authorization Required
     * @param rCode recommend Code
     */
    function _getRCodeOffspring(string memory rCode)
        internal
        view
        returns (string[] memory)
    {
		return db.getRCodeOffspring(rCode);
	}

    /**
     * @dev determine if user invite code is use (db)
     * @param code user invite Code
     * @return isUser bool
     */
    function isUsedCode(string calldata code)
        external
        view
        returns (bool)
    {
		return _isUsedCode(code);
	}

    /**
     * @dev get the user address of the corresponding user invite code (db)
     * Authorization Required
     * @param code user invite Code
     * @return addr address
     */
    function getCodeMapping(string calldata code)
        external
        view
        returns (address)
    {
		return _getCodeMapping(code);
	}

    /**
     * @dev get the user address of the corresponding user id (db)
     * Authorization Required
     * @param uid user id
     * @return addr address
     */
    function getIndexMapping(uint uid)
        external
        view
        returns (address)
    {
        return _getIndexMapping(uid);
	}

    /**
     * @dev get the user address of the corresponding User info (db)
     * @param addr user address
     * @return info info[id,status,level,levelStatus]
     * @return code code
     * @return rCode rCode
     */
    function getUserInfo(address addr)
        external
        view
        returns (uint[4] memory, string memory, string memory)
    {
		return _getUserInfo(addr);
	}

    /**
     * @dev get the rCodeMapping array length of the corresponding recommend Code (db)
     * Authorization Required
     * @param rCode recommend Code
     * @return rCodeMapping array length
     */
    function getRCodeMappingLength(string calldata rCode)
        external
        view
        returns (uint)
    {
		return _getRCodeMappingLength(rCode);
	}
}

/**
 * @dev Interface of the ERC20 standard as defined in the EIP. Does not include
 * the optional functions; to access them see {ERC20Detailed}.
 */
interface IToken {
    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Destroys `amount` tokens from the caller's account, reducing the
     * total supply.
     *
     * If a send hook is registered for the caller, the corresponding function
     * will be called with `data` and empty `operatorData`. See {IERC777Sender}.
     *
     * Emits a {Burned} event.
     *
     * Requirements
     *
     * - the caller must have at least `amount` tokens.
     */
    function burn(uint256 amount, bytes calldata data) external;
}

/**
 * @title Utillibrary
 * @dev This integrates the basic functions.
 */
contract Utillibrary is Rand {
    //lib using list
	using SafeMath for *;
    using Address for address;

    //struct
	struct User {
		uint id;
        uint addupBuyAmonut;
        uint addupBuyTicket;
        uint32 buyTicketRecordIndex;
        mapping(uint32 => BuyTicketData) buyTicketRecord;
        uint investAmount;
        uint investAmountOut;
        uint32 investDataIndex;
        mapping(uint => InvestData) investData;
        uint8 teamLevel;
        uint8 teamLevelLockDemotion;
        uint32 refEffectiveMans;
        uint refEffectiveInvestAmount;
        mapping(uint8 => uint) teamAchievememt;
        mapping(uint8 => uint32) rewardIndex;
        mapping(uint8 => mapping(uint32 => AwardData)) rewardData;
        uint takeWallet_ETT;
        uint addupTakeWallet_ETT;
        uint takeWallet_ETH;
        uint addupTakeWallet_ETH;
        uint32 sgnInDataIndex;
        mapping(uint => SignInData) sgnInData;
        uint bonusStaticAmount;
		uint bonusDynamicAmonut;
        uint burnTokenAmount;
        mapping(uint8 => uint32) cashOutIndex; 
        mapping(uint8 => mapping(uint32 => CashOutData)) cashOutData;
	}

    struct ResonanceData {
        uint40 time;
        uint ratio;
        uint sellMoney;
        uint burnMoney;
        uint poundageMoney;
	}

    struct BuyTicketData {
        uint40 time;
        uint money;
        uint exchangeMoney;
        uint ratio;
        uint8 buyType;
	}

    struct InvestData {
        uint money;
        uint adduoStaticBonus;
        uint adduoDynamicBonus;
        uint8 status;
        uint8 level;
        uint40 investTime;
        uint40 lastRwTime;
        uint40 outTime;
	}

	struct AwardData {
        uint40 time;
        uint amount;
	}

    struct SignInData {
        uint40 time;
        uint amount;
	}

    struct CashOutData {
        uint40 time;
        uint amount;
	}

    //Loglist
    event BuyTicketEvent(address indexed _addr, uint _value, uint _ratio, uint _value2, uint time);
    event InvestEvent(address indexed _addr, string _code, string _rCode, uint _value, uint time);

    //ERC Token addr
    address internal EntranceTicketToken;

    //base param setting
	address internal devAddr;
	address internal foundationAddr;

    mapping(uint => uint) internal DaySellMapping;
    mapping(uint => uint) internal DayInvestMapping;

    mapping(uint => uint) internal DayETTCashOutMapping;
    mapping(uint => uint) internal DayETHCashOutMapping;

    //resonance
    uint internal rid = 1;
    mapping(uint => ResonanceData) internal resonanceDataMapping;

    //address User Mapping
	mapping(address => User) internal userMapping;

    //Loglist
    event TransferEvent(address indexed _from, address indexed _to, uint _value, uint time);
    event TransferTokenEvent(address indexed _token, address indexed _from, address indexed _to, uint _value, uint time);

    //base param setting
    uint internal ETHWei = 1 ether;
    uint internal ETTWei = 10 ** 18;
    uint internal ETH_ETTWei_Ratio = 1 ether;

    //paramsMapping
    mapping(uint => uint) internal paramsMapping;

    mapping(uint => uint) internal TempVariable_Elite;

    /**
     * @dev modifier to scope access to a Contract (uses tx.origin and msg.sender)
     */
	modifier isHuman() {
		require(msg.sender == tx.origin, "humans only");
		_;
	}

    /**
     * @dev check Zero Addr
     */
	modifier checkZeroAddr(address addr) {
		require(addr != address(0), "zero addr");
		_;
	}

    /**
     * @dev check Addr is Contract
     */
	modifier checkIsContract(address addr) {
		require(addr.isContract(), "not token addr");
		_;
	}

    /**
     * @dev Transfer to designated user
     * @param _addr user address
     * @param _val transfer-out amount
     */
	function sendToUser(address payable _addr, uint _val)
        internal
        checkZeroAddr(_addr)
    {
		if (_val > 0) {
            _addr.transfer(_val);
		}
	}

    /**
     * @dev Transfer to designated user
     * @param _taddr token address
     * @param _addr user address
     * @param _val transfer-out amount
     */
	function sendTokenToUser(address _taddr, address _addr, uint _val)
        internal
        checkZeroAddr(_addr)
        checkIsContract(_taddr)
    {
		if (_val > 0) {
            IToken(_taddr).transfer(_addr, _val);
		}
	}

    /**
     * @dev Gets the amount from the specified user
     * @param _taddr token address
     * @param _addr user address
     * @param _val transfer-get amount
     */
	function getTokenFormUser(address _taddr, address _addr, uint _val)
        internal
        checkZeroAddr(_addr)
        checkIsContract(_taddr)
    {
		if (_val > 0) {
            IToken(_taddr).transferFrom(_addr, address(this), _val);
		}
	}

    /**
     * @dev burn money
     * @param _taddr token address
     * @param _val burn amount
     */
	function burnToken(address _taddr, uint _val)
        internal
        checkIsContract(_taddr)
    {
		if (_val > 0) {
            IToken(_taddr).burn(_val, "");
		}
	}

    /**
     * @dev Gets the current day index
     * @return day index
     */
	function getDayIndex()
        internal
        view
        returns (uint)
    {
		return now / 1 days;
	}

    /**
     * @dev Check and correct transfer amount
     * @param sendMoney transfer-out amount
     * @return bool,amount
     */
	function isEnoughTokneBalance(address _taddr, uint sendMoney)
        internal
        view
        returns (bool, uint tokneBalance)
    {
        tokneBalance = IToken(_taddr).balanceOf(address(this));
		if (sendMoney >= tokneBalance) {
			return (false, tokneBalance);
		} else {
			return (true, sendMoney);
		}
	}

    /**
     * @dev Check and correct transfer amount
     * @param sendMoney transfer-out amount
     * @return bool,amount
     */
	function isEnoughBalance(uint sendMoney)
        internal
        view
        returns (bool, uint)
    {
		if (sendMoney >= address(this).balance) {
			return (false, address(this).balance);
		} else {
			return (true, 0);
		}
	}

    /**
     * @dev Gets the get Random
     * @param min Random min
     * @param max Random max
     * @return range random Random
     */
    function randRange(uint min, uint max)
        internal
        returns(uint)
    {
        //check index
        require(max > min, "invalid Range");
        return rand(max - min + 1) + min;
    }

    /**
     * @dev get scale for the Algebra (*scale/1000)
     * @param algebra algebra
     * @return scale
     */
	function getScaleByAlgebra(uint algebra)
        internal
        view
        returns (uint)
    {
		if (algebra >= 1 && algebra <= 3) {
			return paramsMapping[6000 + algebra];
		}
		if (algebra >= 4 && algebra <= 9) {
			return paramsMapping[6004];
		}
		if (algebra >= 10 && algebra <= 15) {
			return paramsMapping[6005];
		}
		return 0;
	}

    /**
     * @dev get scale for the level (*scale/1000)
     * @param level level
     * @return scale
     */
	function getScaleByLevel(uint level)
        internal
        view
        returns (uint)
    {
		if (level >= 1 && level <= 4) {
			return paramsMapping[5110 + level];
		}
		return 0;
	}

    /**
     * @dev get user level (time limit)
     * @param level_v1 level (v1)
     * @param level_v2 level (v2)
     * @param levelStatus level Status (v1)
     * @param limitTime level (v1) Valid time
     * @param levelLockDemotion level (v2) Lock Demotion
     * @return level
     */
	function getLevelByValidTime(uint8 level_v1, uint8 level_v2, uint8 levelStatus, uint limitTime, uint8 levelLockDemotion)
        internal
        view
        returns (uint8)
    {
        if(levelLockDemotion == 1) {
            return level_v2;
        }
		if(levelStatus == 1 && limitTime >= now && level_v1 > level_v2) {
            return level_v1;
        }
		return level_v2;
	}

    /**
     * @dev countBonus AwardData
     * @param user user storage
     * @param bonusAmount Bonus Amount
     * @param _type countBonus type (0 static, 1 share, 2 team, 3 elite, 4 signIn)
     */
    function countBonus_AwardData(User storage user, uint bonusAmount, uint8 _type)
        internal
    {
        AwardData storage awData = user.rewardData[_type][user.rewardIndex[_type]];
        awData.amount += bonusAmount;
	}
}

contract GME_Code is DBUtilli, Utillibrary{
    //lib using list
	using SafeMath for *;
    using String for string;

    /**
     * @dev the content of contract is Beginning
     */
	constructor (
        address _dbAddr,
        address _EntranceTicketAddr
    )
        DBUtilli(_dbAddr)
        public
    {
        EntranceTicketToken = _EntranceTicketAddr;
        devAddr = address(0x430E84EcDB0e23be716df766Cf1568329F83c345);
        foundationAddr = address(0x430E84EcDB0e23be716df766Cf1568329F83c345);

        //init params
        //start Time setting
        paramsMapping[0] = 0;
        paramsMapping[1] = 1;
        paramsMapping[10] = 0;

        paramsMapping[1001] = now + 60 days;

        paramsMapping[2001] = 10 * ETH_ETTWei_Ratio;
        paramsMapping[2002] = 5000 * ETH_ETTWei_Ratio;
        paramsMapping[2003] = 200000 * ETTWei;
        paramsMapping[2004] = 100;
        paramsMapping[2101] = ETHWei / 10;

        paramsMapping[2201] = 0;
        paramsMapping[2202] = 10;

        paramsMapping[3001] = 1 * ETHWei;
        paramsMapping[3002] = 3 * ETHWei;
        paramsMapping[3003] = 10 * ETHWei;
        paramsMapping[3004] = 20 * ETHWei;
        paramsMapping[3005] = 30 * ETHWei;

        paramsMapping[3011] = 3000;
        paramsMapping[3012] = 3000;
        paramsMapping[3013] = 3000;
        paramsMapping[3014] = 3000;
        paramsMapping[3015] = 3500;

        paramsMapping[3101] = 100;

        paramsMapping[4001] = 20;

        paramsMapping[5001] = 8;
        paramsMapping[5002] = 10;
        paramsMapping[5003] = 12;
        paramsMapping[5004] = 15;

        paramsMapping[5011] = 1000 * ETHWei;
        paramsMapping[5012] = 2500 * ETHWei;
        paramsMapping[5013] = 6500 * ETHWei;
        paramsMapping[5014] = 15000 * ETHWei;

        paramsMapping[5111] = 50;
        paramsMapping[5112] = 80;
        paramsMapping[5113] = 120;
        paramsMapping[5114] = 160;
        paramsMapping[5201] = 50;

        paramsMapping[6001] = 500;
        paramsMapping[6002] = 200;
        paramsMapping[6003] = 100;
        paramsMapping[6004] = 50;
        paramsMapping[6005] = 10; 
        paramsMapping[6101] = 3 * ETHWei;

        paramsMapping[7001] = ETTWei / 10;
        paramsMapping[7002] = ETTWei * 10;
        paramsMapping[7011] = 1;

        paramsMapping[8001] = 100;

        paramsMapping[8002] = 100 * ETTWei;

        paramsMapping[9001] = 50;
        paramsMapping[9101] = 0;
        paramsMapping[9102] = 0;

        paramsMapping[9201] = 1000 * ETHWei; 

        paramsMapping[10001] = 10;
        paramsMapping[10002] = 100 * ETHWei;
        paramsMapping[10011] = 100;
        paramsMapping[10012] = 200;
        paramsMapping[10013] = 300;
        paramsMapping[10014] = 400;

        //init ResonanceData
        ResonanceData storage resonance = resonanceDataMapping[rid];
        resonance.time = uint40(now);
        resonance.ratio = 5000 * ETH_ETTWei_Ratio;

        paramsMapping[0] = now;
		paramsMapping[1] = 0;
	}

    /**
     * @dev This contract supports receive
     */
    receive() external payable
    { 

    }

    // /**
    //  * @dev This contract does not support receive
    //  */
    // fallback() external payable{ }

    /**
     * @dev modifier check contract is Open
     */
	modifier _isOpen() {
		require(isOpen(), "no open");
		_;
	}

    /**
     * @dev check User ID
     * @param user user storage
     * @return bool is reg
     */
    function initUserID(User storage user)
        internal
        returns (bool)
    {
        if (user.id == 0) {
            uint[4] memory user_data;
            (user_data, , ) = _getUserInfo(msg.sender);
            user.id = user_data[0];
		}
        return user.id == 0;
	}

    /**
     * @dev check User ID
     * @param uid user ID
     */
    function checkUserID(uint uid)
        internal
        pure
    {
        require(uid != 0, "user not exist");
	}

    /**
     * @dev create invite Code
     * @return inviteCode invite Code
     */
    function getInviteCode()
        internal
        returns (string memory inviteCode)
    {
        uint random = rand(56800235584);
        if (random > 916132832) {
            inviteCode = toStringFromUint256(random);
            if (!_isUsedCode(inviteCode)) {
                return inviteCode;
            } else {
                return getInviteCode();
            }
        } else {
            return getInviteCode();
        }
	}

    /**
     * @dev Converts a `uint256` to its ASCII `string` representation.
     */
    function toStringFromUint256(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 62;
        }
        bytes memory buffer = new bytes(digits);
        temp = value;

        uint8 temp2;
        while (temp != 0) {
            temp2 = uint8(temp % 62);
            if (temp2 >= 36) {
                buffer[--digits] = byte(61 + temp2);
            } else if (temp2 >= 10) {
                buffer[--digits] = byte(55 + temp2);
            } else {
                buffer[--digits] = byte(48 + temp2);
            }
            temp /= 62;
        }
        return string(buffer);
    }

    /**
     * @dev To buy tickets
     */
	function buyTicket()
        external
        payable
        isHuman()
    {
        _buyTicket(msg.sender);
	}

    /**
     * @dev To buy tickets Airdrop
     */
	function buyTicket_Airdrop()
        external
        payable
        isHuman()
    {
        _buyTicket(msg.sender);
	}

    /**
     * @dev To buy tickets
     * @param addr user addressrd
     */
	function _buyTicket(address addr)
        internal
        _isOpen()
    {
        uint money = msg.value;

        require(money >= paramsMapping[2101], "invalid buy range");

		User storage user = userMapping[addr];
        initUserID(user);

        uint ratio = resonanceDataMapping[rid].ratio;
        uint ETTMoney = money.mul(ratio).div(ETH_ETTWei_Ratio);
        
        if(paramsMapping[2201] == 1 && paramsMapping[2202] > 0) {
            uint giftETTMoney = ETTMoney * paramsMapping[2202] / 1000;
            ETTMoney += giftETTMoney;
        }

        DaySellMapping[getDayIndex()] += ETTMoney;

        user.addupBuyAmonut += money;
        user.addupBuyTicket += ETTMoney;

        //send ETT Token to User
        sendTokenToUser(EntranceTicketToken, addr, ETTMoney);

        //update Ratio
        updateRatio(ETTMoney, 0, 0);

        //shunt
        sendToUser(devAddr.toPayable(), money);

        BuyTicketData storage buyTicketData = user.buyTicketRecord[user.buyTicketRecordIndex];
        buyTicketData.time = uint40(now);
        buyTicketData.money = money;
        buyTicketData.exchangeMoney = ETTMoney;
        buyTicketData.ratio = ratio;
        buyTicketData.buyType = 0;
        user.buyTicketRecordIndex ++;

        emit BuyTicketEvent(addr, money, ratio, ETTMoney, now);
	}

        /**
     * @dev the invest of contract is Beginning
     * @param code user invite Code
     * @param rCode recommend code
     */
    function invest(string calldata code, string calldata rCode)
        external
        payable
        isHuman()
    {
        _invest(msg.sender, msg.value, code, rCode, true, 0);
    }

    /**
     * @dev the invest Airdrop
     */
    function invest_Airdrop()
        external
        payable
        isHuman()
    {
        _invest_Airdrop();
    }

    /**
     * @dev the invest of contract is Beginning
     */
    function _invest_Airdrop()
        internal
    {
        address addr = msg.sender;
        //_buyTicket(addr);

        User storage user = userMapping[addr];

        string memory code = "";
        string memory rCode = "";

        if (initUserID(user)) {
            require(_getCurrentUserID() != 0, "Not Find first user");
            address rAddr = _getIndexMapping(1);
            (, rCode, ) = _getUserInfo(rAddr);
            code = getInviteCode();
            _registerUser(addr, code, rCode);
            initUserID(user);
        }

        uint money = msg.value;
        require(money >= paramsMapping[3001] + paramsMapping[3001].mul(paramsMapping[3101]).div(1000),"invalid invest range");
        if(user.investDataIndex == 0) {
            require(money < paramsMapping[3003] + paramsMapping[3003].mul(paramsMapping[3101]).div(1000),"invalid first invest range");
        } else {
            require(user.investData[user.investDataIndex - 1].status == 1,"Has invested");
        }

        uint moneyFree = money.mul(paramsMapping[3101]).div(1000);

        _invest(addr, money.sub(moneyFree), code, rCode, false, moneyFree);
    }

    /**
     * @dev the invest of contract is Beginning
     * @param addr user addressrd
     * @param money invest money
     * @param code user invite Code
     * @param rCode recommend code
     * @param isGetETTFee is Get ETT Token Fee
     */
    function _invest(address addr, uint money, string memory code, string memory rCode, bool isGetETTFee, uint moneyFree)
        internal
        isHuman()
        _isOpen()
    {
        require(money >= paramsMapping[3001], "invalid invest range");

		User storage user = userMapping[addr];

		if (initUserID(user)) {
            _registerUser(addr, code, rCode);
            initUserID(user);
		}

        (, , rCode) = _getUserInfo(addr);

        if(user.investDataIndex == 0) {
            require(money < paramsMapping[3003],"invalid first invest range");
        } else {
            require(user.investData[user.investDataIndex - 1].status == 1,"Has invested");
        }

        uint ratio = resonanceDataMapping[rid].ratio;
        uint ETTMoney = money.mul(ratio).mul(paramsMapping[3101]).div(ETH_ETTWei_Ratio).div(1000);

        if(isGetETTFee) {
            //send ETT Token to Contract
            getTokenFormUser(EntranceTicketToken, addr, ETTMoney);

            burnToken(EntranceTicketToken, ETTMoney);
            user.burnTokenAmount += ETTMoney;

            //update Ratio
            updateRatio(0, ETTMoney, 0);
        } else {
            //buyTicket
            // uint ratio = resonanceDataMapping[rid].ratio;
            uint ETTMoney_moneyFree = moneyFree.mul(ratio).div(ETH_ETTWei_Ratio);

            DaySellMapping[getDayIndex()] += ETTMoney_moneyFree;

            user.addupBuyAmonut += moneyFree;
            user.addupBuyTicket += ETTMoney_moneyFree;

            //shunt
            sendToUser(devAddr.toPayable(), moneyFree);

            BuyTicketData storage buyTicketData = user.buyTicketRecord[user.buyTicketRecordIndex];
            buyTicketData.time = uint40(now);
            buyTicketData.money = moneyFree;
            buyTicketData.exchangeMoney = ETTMoney_moneyFree;
            buyTicketData.ratio = ratio;
            buyTicketData.buyType = 0;
            user.buyTicketRecordIndex ++;

            emit BuyTicketEvent(addr, moneyFree, ratio, ETTMoney_moneyFree, now);

            //invest
            if(ETTMoney_moneyFree > ETTMoney){
                uint ETTMoney_Refund = ETTMoney_moneyFree - ETTMoney;
                //send ETT Token to User -- Refund
                sendTokenToUser(EntranceTicketToken, addr, ETTMoney_Refund);
            }
            
            burnToken(EntranceTicketToken, ETTMoney);
            user.burnTokenAmount += ETTMoney;

            //update Ratio
            updateRatio(ETTMoney_moneyFree, ETTMoney, 0);
        }

        //shunt
        sendToUser(foundationAddr.toPayable(), money);

        paramsMapping[54] += money;
        DayInvestMapping[getDayIndex()] += money;

        //update User info
        user.investAmount += money;

        InvestData storage _investData = user.investData[user.investDataIndex];
        _investData.money = money;  
        _investData.investTime = uint40(now);
        _investData.lastRwTime = uint40(now);

        if(money >= paramsMapping[3005]) {
            _investData.level = 5;
        }
        else if(money >= paramsMapping[3004]) {
            _investData.level = 4;
        }
        else if(money >= paramsMapping[3003]) {
            _investData.level = 3;
        }
        else if(money >= paramsMapping[3002]) {
            _investData.level = 2;
        }
        else if(money >= paramsMapping[3001]) {
            _investData.level = 1;
        }
        user.investDataIndex ++;

        paramsMapping[9101] += money * paramsMapping[9001] / 1000;
        if(paramsMapping[9102] == 0) {
            paramsMapping[9102] = now;
        }
        paramsMapping[9102] += 3 hours;
        if(paramsMapping[9102] - now > 72 hours) {
            paramsMapping[9102] = now + 72 hours;
        }

        paramsMapping[10] += money * paramsMapping[10001] / 1000;


        updateUser_Parent(rCode, money, 1);

        emit InvestEvent(addr, code, rCode, money, now);
	}

    /**
     * @dev settlement Bonus All
     */
    function settlement()
        external
        isHuman()
        _isOpen()
    {
		User storage user = userMapping[msg.sender];
        initUserID(user);
        checkUserID(user.id);

        uint amountSettlement_ETH = 0;
        uint amountSettlement_ETT = 0;

        //-----------Static Start
        if(settlement_Static(msg.sender)) {
            amountSettlement_ETH += settlement_AwardData(msg.sender, 0);
        }
        //-----------Static End

        //-----------share Start
        amountSettlement_ETH += settlement_AwardData(msg.sender, 1);
        //-----------share End

        //-----------team Start
        amountSettlement_ETH += settlement_AwardData(msg.sender, 2);
        //-----------team End

        //-----------elite Start
        amountSettlement_ETH += settlement_AwardData(msg.sender, 3);
        //-----------elite End

        //-----------signIn Start
        amountSettlement_ETT += settlement_AwardData(msg.sender, 4);
        //-----------signIn End

        if (amountSettlement_ETH > 0) {
            // uint ratio = resonanceDataMapping[rid].ratio;
            uint poundageMoney_ETH = amountSettlement_ETH.mul(resonanceDataMapping[rid].ratio).div(ETH_ETTWei_Ratio).mul(paramsMapping[8001]).div(1000);

            //send ETT Token to Contract
            getTokenFormUser(EntranceTicketToken, msg.sender, poundageMoney_ETH);

            //update Ratio
            updateRatio(0, 0, poundageMoney_ETH);
        }
	}

    /**
     * @dev SignIn
     */
    function SignIn()
        external
        isHuman()
        _isOpen()
    {
		User storage user = userMapping[msg.sender];
        initUserID(user);
		checkUserID(user.id);

        require(paramsMapping[7011] == 1, "SignIn Not Open"); 

        //check time 
        if (user.sgnInDataIndex != 0) {
            require(now / 1 days >= (user.sgnInData[user.sgnInDataIndex - 1].time + 1 days) / 1 days, "today signed"); 
        }

        uint ETTMoney = randRange(paramsMapping[7001] / 10000000000000000, paramsMapping[7002] / 10000000000000000) * 10000000000000000;

        SignInData storage signInData = user.sgnInData[user.sgnInDataIndex];
        user.sgnInDataIndex ++;
        signInData.time = uint40(now);
        signInData.amount = ETTMoney;

        countBonus_AwardData(user, ETTMoney, 4);

        //Addup
        paramsMapping[55] += ETTMoney;
    }

    /**
     * @dev Take ETT And ETH
     */
    function Take_All()
        external
        isHuman()
    {
        User storage user = userMapping[msg.sender];
        initUserID(user);
        checkUserID(user.id);

        bool isTakeSucceed = false;

        //Take_ETT Start
        // require(user.takeWallet_ETT > 0 ,"invalid amount ETT");
        if(user.takeWallet_ETT > paramsMapping[8002]) {
            uint amount = user.takeWallet_ETT;
            user.takeWallet_ETT = 0;

            bool isEnough;
            (isEnough, ) = isEnoughTokneBalance(EntranceTicketToken, amount);
            require(isEnough, "not enough balance ETT");
            user.addupTakeWallet_ETT += amount;

            //send ETT Token to User
            sendTokenToUser(EntranceTicketToken, msg.sender, amount);

            CashOutData storage _cashOutData = user.cashOutData[0][user.cashOutIndex[0]];
            _cashOutData.time = uint40(now);
            _cashOutData.amount = amount;
            user.cashOutIndex[0]++;
            DayETTCashOutMapping[getDayIndex()] += amount;
            paramsMapping[57]+= amount;
            isTakeSucceed = true;
        }
        //Take_ETT end

        //Take_ETH Start
        if(user.takeWallet_ETH > 0) {
            uint amount = user.takeWallet_ETH;
            user.takeWallet_ETH = 0;

            bool isEnough;
            (isEnough, ) = isEnoughBalance(amount);
            require(isEnough, "not enough balance ETH");

            user.addupTakeWallet_ETH += amount;

            //send ETH to User
            sendToUser(msg.sender, amount);

            CashOutData storage _cashOutData = user.cashOutData[1][user.cashOutIndex[1]];
            _cashOutData.time = uint40(now);
            _cashOutData.amount = amount;
            user.cashOutIndex[1]++;
            DayETHCashOutMapping[getDayIndex()] += amount;
            paramsMapping[58]+= amount;
            isTakeSucceed = true;
        }  
        //Take_ETH end

        require(isTakeSucceed, "Take fai.");
	}

    /**
     * @dev determine if contract open
     * @return bool
     */
	function isOpen()
        public
        view
        returns (bool)
    {
		return paramsMapping[0] != 0 && now > paramsMapping[0];
	}

    /**
     * @dev update Resonance Ratio
     * @param sellMoney sell ETT amount
     * @param burnMoney buy ETT amount
     * @param poundageMoney poundage ETT amount
     */
	function updateRatio(uint sellMoney, uint burnMoney,uint poundageMoney)
        private
    {
        ResonanceData storage resonance = resonanceDataMapping[rid];
        //Addup Sell ETT
        resonance.sellMoney += sellMoney;
        paramsMapping[51] += sellMoney;
        //Addup burn ETT
        resonance.burnMoney += burnMoney;
        paramsMapping[52] += burnMoney;
        //Addup Poundage ETT
        resonance.poundageMoney += poundageMoney;
        paramsMapping[53] += poundageMoney;
        //check
        uint newRatio = 0;
        uint totalAmount = resonance.sellMoney + resonance.burnMoney + resonance.poundageMoney;
        if(totalAmount >= paramsMapping[2003]) {
            newRatio = resonance.ratio - (resonance.ratio * paramsMapping[2004] / 1000);
            if(newRatio < paramsMapping[2001]) {
                newRatio = paramsMapping[2001];
            }
        }
        if (newRatio > 0) {
            rid ++;
            resonance = resonanceDataMapping[rid];
            resonance.time = uint40(now);
            resonance.ratio = newRatio;
            //Continuous rise
            if(sellMoney > 0) {
                resonance.sellMoney = totalAmount - paramsMapping[2003];
            }
            if(burnMoney > 0) {
                resonance.burnMoney = totalAmount - paramsMapping[2003];
            }
            if(poundageMoney > 0) {
                resonance.poundageMoney = totalAmount - paramsMapping[2003];
            }
            updateRatio(0, 0, 0);
        }
	}

    /**
     * @dev update Parent User
     * @param rCode user recommend code
     * @param money invest money
     * @param _type chenag type: 1 add 0 out
     */
	function updateUser_Parent(string memory rCode, uint money, uint8 _type)
        private
    {
		string memory tmpReferrerCode = rCode;
		for (uint i = 1; i <= 15; i++) {
			if (tmpReferrerCode.compareStr("")) {
				break;
			}

            address userAddress = _getCodeMapping(tmpReferrerCode);
            User storage user = userMapping[userAddress];

            //-----------updateUser_Parent Start
            if (i == 1) {
                if (_type == 1) {
                    user.refEffectiveMans++;
                    user.refEffectiveInvestAmount += money;
                } else if (_type == 0) {
                    user.refEffectiveMans--;
                    user.refEffectiveInvestAmount -= money;
                }
            }
            if (i <= 8) {
                updateUser_Level(user, money, 0, _type);
            } else if (i <= 10) {
                updateUser_Level(user, money, 1, _type);
            } else if (i <= 12) {
                updateUser_Level(user, money, 2, _type);
            } else if (i <= 15) {
                updateUser_Level(user, money, 3, _type);
            }
            //-----------updateUser_Parent End

            (, , tmpReferrerCode) = _getUserInfo(userAddress);
		}
	}

    /**
     * @dev update Parent User
     * @param user user storage
     * @param money invest money
     * @param _indexTeam chenag Team Achievememt:0 (1-8 generations),1 (9-10 generations),2 (11-12 generations),3 (12-15 generations)
     * @param _type chenag type: 1 add 0 out
     */
	function updateUser_Level(User storage user, uint money, uint8 _indexTeam, uint8 _type)
        private
    {
		if (_type == 1) {
            user.teamAchievememt[_indexTeam] += money;
        } else if (_type == 0) {
            user.teamAchievememt[_indexTeam] -= money;
        }
        //check and user teamLevel
        uint8 teamLevel = user.teamLevel;
        if(user.refEffectiveMans >= paramsMapping[5004] 
            && user.teamAchievememt[0] + user.teamAchievememt[1] + user.teamAchievememt[2] + user.teamAchievememt[3] >= paramsMapping[5014]
        )
        {
            teamLevel = 4;
        }
        else if(user.refEffectiveMans >= paramsMapping[5003] 
            && user.teamAchievememt[0] + user.teamAchievememt[1] + user.teamAchievememt[2] >= paramsMapping[5013]
        )
        {
            teamLevel = 3;
        }
        else if(user.refEffectiveMans >= paramsMapping[5002] 
            && user.teamAchievememt[0] + user.teamAchievememt[1] >= paramsMapping[5012]
        )
        {
            teamLevel = 2;
        }
        else if(user.refEffectiveMans >= paramsMapping[5001] 
            && user.teamAchievememt[0] >= paramsMapping[5011]
        )
        {
            teamLevel = 1;
        }
        else {
            teamLevel = 0;
        }

        if (user.teamLevelLockDemotion == 0 && user.teamLevel != teamLevel) {
            user.teamLevel = teamLevel;
        } else if (user.teamLevelLockDemotion == 1 && user.teamLevel <= teamLevel) {
            user.teamLevel = teamLevel;
            user.teamLevelLockDemotion = 0;
        }
	}

    /**
     * @dev settlement Static Bonus
     * @param addr user addressr
     * @return bool
     */
    function settlement_Static(address addr)
        private
        returns (bool)
    {
		User storage user = userMapping[addr];
        // checkUserID(user.id);

        //reacquire rCode
        string memory rCode;
        uint[4] memory user_data;
        (user_data, , rCode) = _getUserInfo(addr);
        uint user_status = user_data[1];

        if (user.investDataIndex == 0 || user_status == 1) {
            return false;
        }
        //-----------Static Start
        InvestData storage investData = user.investData[user.investDataIndex - 1];
        uint settlementNumber_base = (now - investData.lastRwTime) / 1 days;
        if (investData.status == 0 && settlementNumber_base > 0) {
            uint moneyBonus_base = investData.money * paramsMapping[4001] / 1000;
            uint settlementNumber = settlementNumber_base;
            uint settlementMaxMoney = 0;

            if(investData.money * paramsMapping[3010 + investData.level] / 1000 >= investData.adduoStaticBonus + investData.adduoDynamicBonus) {
                settlementMaxMoney = investData.money * paramsMapping[3010 + investData.level] / 1000 - (investData.adduoStaticBonus + investData.adduoDynamicBonus);
            }
            uint moneyBonus = 0;
            if (moneyBonus_base * settlementNumber > settlementMaxMoney) {
                settlementNumber = settlementMaxMoney / moneyBonus_base;
                if (moneyBonus_base * settlementNumber < settlementMaxMoney) {
                    settlementNumber ++;
                }
                if (settlementNumber > settlementNumber_base) {
                    settlementNumber = settlementNumber_base;
                }
                // moneyBonus = moneyBonus_base * settlementNumber;
                moneyBonus = settlementMaxMoney;
            } else {
                moneyBonus = moneyBonus_base * settlementNumber;
            }

            investData.lastRwTime += uint40(settlementNumber * 1 days);

            update_CheckInvestOut(user, investData, moneyBonus, 0, rCode);

            //Calculate the bonus (Daily Dividend)
            countBonus_DailyDividend(rCode, moneyBonus, investData.money);

            return true;
        } else {
            return false;
        }
        //-----------Static End
	}

    /**
     * @dev Calculate the bonus (Daily Dividend)
     * @param rCode user recommend code
     * @param money base money
     * @param investMoney invest money
     */
	function countBonus_DailyDividend(string memory rCode, uint money, uint investMoney)
        private
    {
        uint baseMoney = money;

        uint maxLevel_team = 0;
        uint haveTakeScale = 0;
        uint lastLevel_team = 0;
        uint lastlevel_team_baseMoney = 0;

		string memory tmpReferrerCode = rCode;

		for (uint i = 1; i <= 21; i++) {
			if (tmpReferrerCode.compareStr("")) {
				break;
			}

            address userAddress = _getCodeMapping(tmpReferrerCode);
			User storage user = userMapping[userAddress];

            //last rRcode and currUserInfo
            uint[4] memory user_data;
            string memory tmpUser_rCode;
            uint user_status = 0;
            (user_data, , tmpUser_rCode) = _getUserInfo(userAddress);
            user_status = user_data[1];

			InvestData storage investData = user.investData[user.investDataIndex - 1];

            //-----------share Start
            if(i <= 15 && user.investDataIndex > 0 && investData.status == 0 && user.refEffectiveMans >= i && user_status == 0) {
                uint moneyBonus = baseMoney * getScaleByAlgebra(i) / 1000;
                //burns
                if (investData.money < paramsMapping[6101] && investData.money < investMoney) {
                    moneyBonus = moneyBonus * investData.money / investMoney;
                }
                if (moneyBonus > 0) {
                    update_CheckInvestOut(user, investData, moneyBonus, 1, tmpUser_rCode);
                }
            }
            //-----------share End

            //-----------team Start
            uint8 userLevel = getLevelByValidTime(uint8(user_data[2]) ,user.teamLevel, uint8(user_data[3]), paramsMapping[1001], user.teamLevelLockDemotion);

            if (userLevel >= 1 && userLevel > maxLevel_team) {
                uint moneyBonus = 0;
                uint userLevelScale = getScaleByLevel(userLevel);
                if(userLevelScale > haveTakeScale) {
                    moneyBonus = baseMoney;
                    moneyBonus = moneyBonus * (userLevelScale - haveTakeScale) / 1000;
                    haveTakeScale += (userLevelScale - haveTakeScale);
                }
                if (moneyBonus > 0 && user.investDataIndex > 0 && investData.status == 0 && user_status == 0) {
                    countBonus_AwardData(user, moneyBonus, 2);
                }
                maxLevel_team = userLevel;
                lastLevel_team = userLevel;
                lastlevel_team_baseMoney = moneyBonus;
            } else if (userLevel >= 1 && userLevel == lastLevel_team) {
                //-----------SameLevel Start
                uint moneyBonus = lastlevel_team_baseMoney * paramsMapping[5201] / 1000;
                if (moneyBonus > 0 && user.investDataIndex > 0 && investData.status == 0 && user_status == 0) {
                    countBonus_AwardData(user, moneyBonus, 2);
                }
                lastLevel_team = 0;
                lastlevel_team_baseMoney = 0;
                //-----------SameLevel End
            } else {
                lastLevel_team = 0;
                lastlevel_team_baseMoney = 0;
            }
            //-----------team End           
            tmpReferrerCode = tmpUser_rCode;
		}
	}

    /**
     * @dev Update and Check Invest Out (all Bonus)
     * @param user user storage
     * @param investData user investData storage
     * @param bonusAmount Bonus Amount
     * @param bonusType 0static 1dynamic
     * @param rCode user rCode
     */
	function update_CheckInvestOut(User storage user, InvestData storage investData, uint bonusAmount, uint8 bonusType, string memory rCode)
        private
    {
        if (investData.status == 0) {
            if (investData.adduoStaticBonus + investData.adduoDynamicBonus + bonusAmount >= investData.money * paramsMapping[3010 + investData.level] / 1000) {
                investData.status = 1;
                investData.outTime = uint40(now);
                updateUser_Parent(rCode, investData.money, 0);

                user.investAmountOut += investData.money;

                bonusAmount = investData.money * paramsMapping[3010 + investData.level] / 1000 - (investData.adduoStaticBonus + investData.adduoDynamicBonus);
            }
            if(bonusType == 0) {
                investData.adduoStaticBonus += bonusAmount;
            } else if(bonusType == 1) {
                investData.adduoDynamicBonus += bonusAmount;
            }

            countBonus_AwardData(user, bonusAmount, bonusType);
        }
	}

    /**
     * @dev settlement AwardData
     * @param addr user addressr
     * @param _type settlement type (0 static, 1 share, 2 team, 3 elite, 4 signIn)
     * @return amount amount
     */
    function settlement_AwardData(address addr, uint8 _type)
        private
        returns (uint amount)
    {
		User storage user = userMapping[addr];

        AwardData storage awData = user.rewardData[_type][user.rewardIndex[_type]];
        if(awData.amount > 0) {
            user.rewardIndex[_type] ++;
            awData.time = uint40(now);
            if(_type == 0) {
                user.takeWallet_ETH += awData.amount;
                user.bonusStaticAmount += awData.amount;
            } else if(_type == 1 || _type == 2 || _type == 3) {
                user.takeWallet_ETH += awData.amount;
                user.bonusDynamicAmonut += awData.amount;
            } else if(_type == 4) {
                uint poundageMoney_ETT = awData.amount * paramsMapping[8001] / 1000;
                user.takeWallet_ETT += awData.amount.sub(poundageMoney_ETT);

                //update Ratio
                updateRatio(0, 0, poundageMoney_ETT);
            }
            amount = awData.amount;
        }
        return amount;
	}

    /**
     * @dev Show contract state view
     * @return info contract  state view
     */
    function stateView()
        external
        view
        returns (uint[40] memory info)
    {
        info[0] = _getCurrentUserID();
        info[1] = paramsMapping[0];
        info[2] = paramsMapping[1];
        info[3] = rid;
        info[4] = resonanceDataMapping[rid].ratio;
        info[5] = resonanceDataMapping[rid].sellMoney;
        info[6] = resonanceDataMapping[rid].time;
        info[7] = paramsMapping[51];
        info[8] = paramsMapping[52];
        info[9] = paramsMapping[54];
        info[10] = DaySellMapping[getDayIndex()];
        info[11] = DayInvestMapping[getDayIndex()];
        info[12] = paramsMapping[3001];
        info[13] = paramsMapping[3002];
        info[14] = paramsMapping[3003];
        info[15] = paramsMapping[3004];
        info[16] = paramsMapping[3005];
        info[17] = paramsMapping[9101];
        info[18] = paramsMapping[9102];
        info[19] = paramsMapping[10];
        info[20] = paramsMapping[55];
        info[21] = paramsMapping[56];
        info[22] = paramsMapping[53];
        info[23] = paramsMapping[3011];
        info[24] = paramsMapping[3012];
        info[25] = paramsMapping[3013];
        info[26] = paramsMapping[3014];
        info[27] = paramsMapping[3015];
        info[28] = paramsMapping[2201];
        info[29] = paramsMapping[2202];
        info[30] = paramsMapping[9201];
        info[31] = paramsMapping[3101];
        info[32] = paramsMapping[7011];
        info[33] = paramsMapping[8001];
        info[34] = paramsMapping[8002];
        info[35] = paramsMapping[4001];
        info[36] = paramsMapping[57];
        info[37] = paramsMapping[58];
        info[38] = DayETTCashOutMapping[getDayIndex()];
        info[39] = DayETHCashOutMapping[getDayIndex()];
        return (info);
	}

    /**
     * @dev get the user info based on user ID
     * @param addr user addressrd
     * @return info user info
     * @return code user code
     * @return rCode user rCode
     * @return raddr user addr
     * @return rID user id
     * @return recommendNumber recommend Number
     */
	function getUserByAddress(
        address addr
    )
        external
        view
        returns (uint[20] memory info, string memory code, string memory rCode, address raddr, uint rID, uint recommendNumber)
    {
        uint[4] memory user_data;
        (user_data, code, rCode) = _getUserInfo(addr);

		User storage user = userMapping[addr];

		info[0] = user_data[0];
        info[1] = user_data[1];
        info[2] = user_data[2];
        info[3] = user_data[3];
        info[4] = user.teamLevel;
        info[5] = user.bonusDynamicAmonut;
        info[6] = user.investAmount;
        info[7] = user.addupBuyAmonut;
        info[8] = user.addupBuyTicket;
        info[9] = user.buyTicketRecordIndex;
        info[10] = user.investDataIndex;
        info[11] = user.sgnInDataIndex;
        info[12] = user.takeWallet_ETH;
        info[13] = user.takeWallet_ETT;
        info[14] = user.refEffectiveInvestAmount;
        info[15] = user.bonusStaticAmount;
        info[16] = user.teamAchievememt[0] + user.teamAchievememt[1] + user.teamAchievememt[2] + user.teamAchievememt[3];

        info[17] = getLevelByValidTime(uint8(user_data[2]) ,user.teamLevel, uint8(user_data[3]), paramsMapping[1001], user.teamLevelLockDemotion);
        info[18] = paramsMapping[1001];
        info[19] = ComputingTeamInformation_Offspring(addr);

        raddr = _getCodeMapping(rCode);

        (user_data, , ) = _getUserInfo(raddr);
        rID = user_data[0];

        recommendNumber= _getRCodeMappingLength(code);

		return (info, code, rCode, raddr, rID, recommendNumber);
	}

    /**
     * @dev get the user info based on user ID
     * @param addr user addressr
     * @return offspring_CodeArr offspring user code
     * @return offspring_info offspring user info
     */
    function getRCodeOffspringByAddress(
        address addr
    )
        external
        view
        returns (string[] memory offspring_CodeArr, uint[][] memory offspring_info)
    {
        string memory code;
        (, code, ) = _getUserInfo(addr);
        offspring_CodeArr = _getRCodeOffspring(code);

        offspring_info = new uint[][](offspring_CodeArr.length);

        for (uint i = 0; i < offspring_info.length; i++) {
            offspring_info[i] = new uint[](3);

            uint[4] memory user_data;
            (user_data, , ) = _getUserInfo(_getCodeMapping(offspring_CodeArr[i]));

            offspring_info[i][0] = user_data[0];
            offspring_info[i][1] = user_data[2];
            User memory user = userMapping[_getCodeMapping(offspring_CodeArr[i])];
            offspring_info[i][2] = user.investAmount;
        }
		return (offspring_CodeArr, offspring_info);
	}

    /**
     * @dev get the Buy Ticket Record Data
     * @param addr user addressrd
     * @param index Buy Ticket Record index
     * @return info Buy Ticket Record data
     */
	function getBuyTicketRecordByAddress(
        address addr,
        uint32 index
    )
        external
        view
        returns (uint[5] memory info)
    {
        User storage user = userMapping[addr];
        BuyTicketData memory buyTicketData = user.buyTicketRecord[index];

        info[0] = buyTicketData.time;//time
        info[1] = buyTicketData.money;//Buy amount
        info[2] = buyTicketData.exchangeMoney;//exchange amount
        info[3] = buyTicketData.ratio;//Resonance amount
        info[4] = buyTicketData.buyType;//0:normal,1:Node

		return (info);
	}

    /**
     * @dev get the Invest Record Data
     * @param addr user addressrd
     * @param index Invest Record index
     * @return info Invest Record data
     */
	function getInvestRecordByAddress(
        address addr,
        uint32 index
    )
        external
        view
        returns (uint[8] memory info)
    {
        User storage user = userMapping[addr];
        InvestData memory investData = user.investData[index];

        info[0] = investData.money;//invest amount
        info[1] = investData.adduoStaticBonus;//add up settlement static bonus amonut
        info[2] = investData.adduoDynamicBonus;//add up settlement dynamic bonus amonut
        info[3] = investData.status;//invest status, 0:normal,1:out
        info[4] = investData.level;//invest level
        info[5] = investData.investTime;//invest time
        info[6] = investData.lastRwTime;//last settlement time
        info[7] = investData.outTime;//out time

		return (info);
	}

    /**
     * @dev get the SignIn Record Data
     * @param addr user addressrd
     * @param index SignIn Record index
     * @return info SignIn Record data
     */
	function getSignInRecordByAddress(
        address addr,
        uint32 index
    )
        external
        view
        returns (uint[2] memory info)
    {
        User storage user = userMapping[addr];       
        SignInData memory signInData = user.sgnInData[index];
        info[0] = signInData.time;//time
        info[1] = signInData.amount;//SignIn get ETT amount
		return (info);
	}

    /**
     * @dev get the Reward Data
     * @param addr user addressrd
     * @param _type settlement type (0 static, 1 share, 2 team, 3 elite, 4 signIn)
     * @param index rewardData index
     * @return info data
     */
	function getRewardDataByAddress(
        address addr,
        uint8 _type,
        uint32 index
    )
        external
        view
        returns (uint[2] memory info, uint)
    {
		User storage user = userMapping[addr];

        info[0] = user.rewardData[_type][index].amount;//raward (type) index
        info[1] = user.rewardData[_type][index].time;//raward (type) index

		return (info, user.rewardIndex[_type]);
	}

    /**
     * @dev get the Cash Out Data
     * @param addr user addressrd
     * @param _type Cash Out Data type (0 ETT, 1 ETH)
     * @param index Cash Out Data index
     * @return info data
     */
	function getCashOutDataByAddress(
        address addr,
        uint8 _type,
        uint32 index
    )
        external
        view
        returns (uint[2] memory info, uint32)
    {
		User storage user = userMapping[addr];

        info[0] = user.cashOutData[_type][index].amount;//cash out (type) index
        info[1] = user.cashOutData[_type][index].time;//cash out (type) index

		return (info, user.cashOutIndex[_type]);
	}

    /**
     * @dev Calculate the bonus (Elite) Start Step0-1
     */
	function countBonus_EliteStart()
        private
        isHuman()
    {
        //Step 1 Start
        require(paramsMapping[10] >= paramsMapping[10002], "Jackpot Not Satisfied"); 
        require(TempVariable_Elite[0] == 0, "Calculate Not End"); 

        TempVariable_Elite[0] = 2;//task Step
        TempVariable_Elite[1000] = paramsMapping[10002]; //paramsMapping[10];
        paramsMapping[10] = paramsMapping[10] - paramsMapping[10002];

        //Calculate limit
        //countBonus_Elite Start

        //init task progress
        TempVariable_Elite[1] = 1;
        TempVariable_Elite[2] = _getCurrentUserID();
        //init
        TempVariable_Elite[101] = 0;
        TempVariable_Elite[102] = 0;
        TempVariable_Elite[103] = 0;
        TempVariable_Elite[104] = 0;
        //Step 1 end
    }

    /**
     * @dev Calculate the bonus (Elite)
     */
	function countBonus_Elite()
        private
        isHuman()
    {
        require(TempVariable_Elite[0] != 0, "Calculate Not Start"); 

        //statistics User Level number
        //Step 2 Start
        if(TempVariable_Elite[0] == 2 || TempVariable_Elite[0] == 3) {
            while(TempVariable_Elite[1] <= TempVariable_Elite[2]) {

                address userAddress = _getIndexMapping(TempVariable_Elite[1]);
                uint[4] memory user_data;
                (user_data, , ) = _getUserInfo(userAddress);

                User storage user = userMapping[userAddress];
                uint8 userLevel = getLevelByValidTime(uint8(user_data[2]) ,user.teamLevel, uint8(user_data[3]), paramsMapping[1001], user.teamLevelLockDemotion);

                if (userLevel > 0) {
                    if (TempVariable_Elite[0] == 2) {
                        TempVariable_Elite[100 + userLevel] ++;                  
                    } else if (TempVariable_Elite[0] == 3 && TempVariable_Elite[100 + userLevel] > 0) {
                        uint moneyBonus = TempVariable_Elite[1000] * paramsMapping[10010 + userLevel] / 1000 / TempVariable_Elite[100 + userLevel];
                        countBonus_AwardData(user, moneyBonus, 3);
                    }
                }

                TempVariable_Elite[1]++;

                if (TempVariable_Elite[1] % 300 == 0) {
                    break;
                }
            }
            //Step 2 check
            if (TempVariable_Elite[1] > TempVariable_Elite[2]) {
                TempVariable_Elite[0] ++;//task Step
                //init task progress
                TempVariable_Elite[1] = 1;
            }
        }
        //Step 2 end

        //Step 3 Start 
        if(TempVariable_Elite[0] == 4) {
            TempVariable_Elite[0] = 0;
        }
        //Step 3 end
	}

    function getEliteSettleStatus()
        private
        view
        returns(uint[4] memory info)
    {   
        info[0] = TempVariable_Elite[0];
        info[1] = TempVariable_Elite[1];
        info[2] = TempVariable_Elite[2];
        info[3] = TempVariable_Elite[1000];
        return info;
    }

    /**
     * @dev Computing Team Information Offspring
     * @param addr user addr
     * @return teamNumber
     */
	function ComputingTeamInformation_Offspring
    (
        address addr
    )
        private
        view
        returns (uint teamNumber)
    {
        string memory tmpParentCode;
        (, tmpParentCode, ) = _getUserInfo(addr);

        string[] memory offspring_CodeArr;
        string[] memory offspring_CodeArr_Temp;

        //root offspring
        offspring_CodeArr = _getRCodeOffspring(tmpParentCode);

        for (uint i = 1; i <= 21; i++) {
            offspring_CodeArr_Temp = offspring_CodeArr;

            for (uint j = 0; j < offspring_CodeArr_Temp.length; j++) {
                teamNumber++;
            }

            if (i >= 21) {
                break;
            }

            //offspring info
            uint offspring_CodeLength = 0;
            for (uint j = 0; j < offspring_CodeArr_Temp.length; j++) {
                offspring_CodeLength += _getRCodeMappingLength(offspring_CodeArr_Temp[j]);
            }
            offspring_CodeArr = new string[](offspring_CodeLength);
            uint offspring_CodeArrIndex = 0;
            for (uint j = 0; j < offspring_CodeArr_Temp.length; j++) {
                uint l = _getRCodeMappingLength(offspring_CodeArr_Temp[j]);
                for (uint k = 0; k < l; k++) {
                    offspring_CodeArr[offspring_CodeArrIndex] = _getRCodeMapping(offspring_CodeArr_Temp[j], k);
                    offspring_CodeArrIndex ++;
                }
            }
        }

		return teamNumber;
	}
}