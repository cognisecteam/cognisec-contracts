// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

/*
                 /\
                /  \
               / /\ \
              / /  \ \
             / /____\ \
            /__________\
            \          /
             \        /
              \______/

  Cognisec provides privacy-focused access to secure AI and digital finance.
  Learn more at https://cognisec.org.
*/

/// @title Cognisec Bunker
/// @notice A user-owned account with distinct AI-billing and DeFi-execution policies.
/// @dev Deploy behind a Cognisec-controlled beacon proxy; owner signatures authorize account actions.
contract CognisecBunker is Initializable {
    enum Kind {
        AI,
        DEFI
    }

    struct Reservation {
        address asset;
        uint256 amount;
        uint256 day;
        uint8 state;
    }

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("Cognisec Bunker");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address asset,address recipient,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 private constant DAILY_LIMIT_TYPEHASH =
        keccak256("SetDailyLimit(address asset,uint256 limit,uint256 nonce,uint256 deadline)");
    bytes32 private constant EXECUTE_TYPEHASH =
        keccak256("Execute(address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant SWAP_TYPEHASH =
        keccak256("Swap(address assetIn,address assetOut,uint256 amountIn,uint256 minAmountOut,bytes32 dataHash,uint256 nonce,uint256 deadline)");
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes4 private constant BALANCE_OF_SELECTOR = 0x70a08231;
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb;
    bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3;
    bytes4 private constant ALLOWANCE_SELECTOR = 0xdd62ed3e;
    address private constant KYBERSWAP_ROUTER =
        0x6131B5fae19EA4f9D964eAc0408E4408b66337b5;

    address public owner;
    Kind public kind;
    address public billingController;
    address public treasury;
    uint256 public ownerNonce;
    mapping(address asset => uint256 amount) public reservedAmount;
    mapping(address asset => uint256 amount) public dailyLimit;
    mapping(address asset => mapping(uint256 day => uint256 amount)) public spentByDay;
    mapping(bytes32 reservationId => Reservation reservation) public reservations;
    uint256 private entered;
    uint256[40] private __gap;

    event Deposited(address indexed asset, address indexed sender, uint256 amount);
    event Withdrawn(address indexed asset, address indexed recipient, uint256 amount);
    event DailyLimitUpdated(address indexed asset, uint256 limit);
    event Executed(address indexed target, uint256 value, bytes32 dataHash);
    event SwapExecuted(
        address indexed assetIn,
        address indexed assetOut,
        uint256 amountIn,
        uint256 amountOut,
        uint256 minAmountOut,
        bytes32 routeDataHash
    );
    event UsageReserved(bytes32 indexed reservationId, address indexed asset, uint256 amount);
    event UsageSettled(bytes32 indexed reservationId, address indexed asset, uint256 amount);
    event UsageReleased(bytes32 indexed reservationId, address indexed asset, uint256 amount);

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidSignature();
    error ExpiredSignature();
    error InvalidNonce();
    error WrongBunkerKind();
    error InvalidAmount();
    error InsufficientAvailableBalance();
    error DailyLimitExceeded();
    error InvalidReservation();
    error TransferFailed();
    error ReentrantCall();
    error ExternalCallFailed(bytes returnData);
    error UnsupportedAsset();
    error InvalidSwap();
    error DirectExecutionDisabled();
    error ApprovalFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyBillingController() {
        if (msg.sender != billingController) revert Unauthorized();
        if (kind != Kind.AI) revert WrongBunkerKind();
        _;
    }

    modifier nonReentrant() {
        if (entered != 1) revert ReentrantCall();
        entered = 2;
        _;
        entered = 1;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner_,
        Kind kind_,
        address billingController_,
        address treasury_
    ) external initializer {
        if (owner_ == address(0) || billingController_ == address(0) || treasury_ == address(0)) {
            revert InvalidConfiguration();
        }
        owner = owner_;
        kind = kind_;
        billingController = billingController_;
        treasury = treasury_;
        entered = 1;
    }

    receive() external payable {
        emit Deposited(address(0), msg.sender, msg.value);
    }

    function availableBalance(address asset) public view returns (uint256) {
        uint256 balance = _balanceOf(asset);
        uint256 reserved = reservedAmount[asset];
        return balance > reserved ? balance - reserved : 0;
    }

    function withdraw(
        address asset,
        address payable recipient,
        uint256 amount
    ) external onlyOwner nonReentrant {
        _withdraw(asset, recipient, amount);
    }

    function withdrawWithSignature(
        address asset,
        address payable recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        bytes32 structHash = keccak256(
            abi.encode(WITHDRAW_TYPEHASH, asset, recipient, amount, nonce, deadline)
        );
        _consumeOwnerSignature(structHash, nonce, deadline, signature);
        _withdraw(asset, recipient, amount);
    }

    function swapWithSignature(
        address assetIn,
        address assetOut,
        uint256 amountIn,
        uint256 minAmountOut,
        bytes calldata routerData,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant returns (uint256 amountOut) {
        if (kind != Kind.DEFI) revert WrongBunkerKind();
        if (
            assetIn == assetOut ||
            amountIn == 0 ||
            minAmountOut == 0 ||
            !isSupportedAsset(assetIn) ||
            !isSupportedAsset(assetOut)
        ) revert InvalidSwap();

        bytes32 structHash = keccak256(
            abi.encode(
                SWAP_TYPEHASH,
                assetIn,
                assetOut,
                amountIn,
                minAmountOut,
                keccak256(routerData),
                nonce,
                deadline
            )
        );
        _consumeOwnerSignature(structHash, nonce, deadline, signature);
        if (availableBalance(assetIn) < amountIn) revert InsufficientAvailableBalance();

        uint256 outputBalanceBefore = _balanceOf(assetOut);
        if (assetIn == address(0)) {
            (bool nativeSuccess, bytes memory nativeResult) =
                KYBERSWAP_ROUTER.call{value: amountIn}(routerData);
            if (!nativeSuccess) revert ExternalCallFailed(nativeResult);
        } else {
            _safeApprove(assetIn, KYBERSWAP_ROUTER, 0);
            _safeApprove(assetIn, KYBERSWAP_ROUTER, amountIn);
            if (_allowance(assetIn, KYBERSWAP_ROUTER) != amountIn) {
                revert ApprovalFailed();
            }
            (bool success, bytes memory result) = KYBERSWAP_ROUTER.call(routerData);
            if (!success) revert ExternalCallFailed(result);
            _safeApprove(assetIn, KYBERSWAP_ROUTER, 0);
            if (_allowance(assetIn, KYBERSWAP_ROUTER) != 0) {
                revert ApprovalFailed();
            }
        }

        uint256 outputBalanceAfter = _balanceOf(assetOut);
        if (outputBalanceAfter <= outputBalanceBefore) revert InvalidSwap();
        amountOut = outputBalanceAfter - outputBalanceBefore;
        if (amountOut < minAmountOut) revert InvalidSwap();
        emit SwapExecuted(
            assetIn,
            assetOut,
            amountIn,
            amountOut,
            minAmountOut,
            keccak256(routerData)
        );
    }

    function isSupportedAsset(address asset) public pure returns (bool) {
        return
            asset == address(0) ||
            asset == 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168 ||
            asset == 0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC ||
            asset == 0xaF3D76f1834A1d425780943C99Ea8A608f8a93f9 ||
            asset == 0xD5f3879160bc7c32ebb4dC785F8a4F505888de68 ||
            asset == 0x4a0E65A3EcceC6dBe60AE065F2e7bb85Fae35eEa ||
            asset == 0xC9a981FEE1F9DEc688bb123ccDeCc63D0deBFC4e ||
            asset == 0x117cc2133c37B721F49dE2A7a74833232B3B4C0C ||
            asset == 0xa30FA36Db767ad9eD3f7a60fC79526fB4d56D344 ||
            asset == 0x39dBED3a2bd333467115dE45665cC57F813C4571 ||
            asset == 0x020bfC650A365f8BB26819deAAbF3E21291018b4;
    }

    function setDailyLimit(address asset, uint256 limit) external onlyOwner {
        _setDailyLimit(asset, limit);
    }

    function setDailyLimitWithSignature(
        address asset,
        uint256 limit,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(DAILY_LIMIT_TYPEHASH, asset, limit, nonce, deadline)
        );
        _consumeOwnerSignature(structHash, nonce, deadline, signature);
        _setDailyLimit(asset, limit);
    }

    function executeWithSignature(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant returns (bytes memory result) {
        if (kind != Kind.DEFI) revert WrongBunkerKind();
        target;
        value;
        data;
        nonce;
        deadline;
        signature;
        revert DirectExecutionDisabled();
    }

    function reserveUsage(
        address asset,
        uint256 amount,
        bytes32 reservationId
    ) external onlyBillingController {
        if (amount == 0 || reservationId == bytes32(0)) revert InvalidAmount();
        if (reservations[reservationId].state != 0) revert InvalidReservation();

        uint256 day = block.timestamp / 1 days;
        uint256 nextSpent = spentByDay[asset][day] + amount;
        if (nextSpent > dailyLimit[asset]) revert DailyLimitExceeded();
        if (availableBalance(asset) < amount) revert InsufficientAvailableBalance();

        reservedAmount[asset] += amount;
        spentByDay[asset][day] = nextSpent;
        reservations[reservationId] = Reservation({
            asset: asset,
            amount: amount,
            day: day,
            state: 1
        });
        emit UsageReserved(reservationId, asset, amount);
    }

    function settleUsage(bytes32 reservationId) external onlyBillingController nonReentrant {
        Reservation storage reservation = reservations[reservationId];
        if (reservation.state != 1) revert InvalidReservation();

        address asset = reservation.asset;
        uint256 amount = reservation.amount;
        reservation.state = 2;
        reservedAmount[asset] -= amount;
        _transferAsset(asset, payable(treasury), amount);
        emit UsageSettled(reservationId, asset, amount);
    }

    function releaseUsage(bytes32 reservationId) external onlyBillingController {
        Reservation storage reservation = reservations[reservationId];
        if (reservation.state != 1) revert InvalidReservation();

        reservation.state = 3;
        reservedAmount[reservation.asset] -= reservation.amount;
        spentByDay[reservation.asset][reservation.day] -= reservation.amount;
        emit UsageReleased(reservationId, reservation.asset, reservation.amount);
    }

    function _setDailyLimit(address asset, uint256 limit) private {
        if (kind != Kind.AI) revert WrongBunkerKind();
        dailyLimit[asset] = limit;
        emit DailyLimitUpdated(asset, limit);
    }

    function _withdraw(
        address asset,
        address payable recipient,
        uint256 amount
    ) private {
        if (recipient == address(0) || amount == 0) revert InvalidAmount();
        if (kind == Kind.AI) _consumeDailyLimit(asset, amount);
        if (availableBalance(asset) < amount) revert InsufficientAvailableBalance();
        _transferAsset(asset, recipient, amount);
        emit Withdrawn(asset, recipient, amount);
    }

    function _consumeDailyLimit(address asset, uint256 amount) private {
        uint256 day = block.timestamp / 1 days;
        uint256 nextSpent = spentByDay[asset][day] + amount;
        if (nextSpent > dailyLimit[asset]) revert DailyLimitExceeded();
        spentByDay[asset][day] = nextSpent;
    }

    function _safeApprove(address asset, address spender, uint256 amount) private {
        (bool success, bytes memory result) = asset.call(
            abi.encodeWithSelector(APPROVE_SELECTOR, spender, amount)
        );
        if (!success || (result.length != 0 && !abi.decode(result, (bool)))) {
            revert ApprovalFailed();
        }
    }

    function _allowance(address asset, address spender) private view returns (uint256 amount) {
        (bool success, bytes memory result) = asset.staticcall(
            abi.encodeWithSelector(ALLOWANCE_SELECTOR, address(this), spender)
        );
        if (!success || result.length < 32) revert ApprovalFailed();
        amount = abi.decode(result, (uint256));
    }

    function _transferAsset(
        address asset,
        address payable recipient,
        uint256 amount
    ) private {
        if (asset == address(0)) {
            (bool nativeSuccess, ) = recipient.call{value: amount}("");
            if (!nativeSuccess) revert TransferFailed();
            return;
        }

        (bool success, bytes memory result) = asset.call(
            abi.encodeWithSelector(TRANSFER_SELECTOR, recipient, amount)
        );
        if (!success || (result.length != 0 && !abi.decode(result, (bool)))) {
            revert TransferFailed();
        }
    }

    function _balanceOf(address asset) private view returns (uint256 balance) {
        if (asset == address(0)) return address(this).balance;

        (bool success, bytes memory result) = asset.staticcall(
            abi.encodeWithSelector(BALANCE_OF_SELECTOR, address(this))
        );
        if (!success || result.length < 32) revert InvalidConfiguration();
        balance = abi.decode(result, (uint256));
    }

    function _consumeOwnerSignature(
        bytes32 structHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) private {
        if (block.timestamp > deadline) revert ExpiredSignature();
        if (nonce != ownerNonce) revert InvalidNonce();

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );
        if (_recover(digest, signature) != owner) revert InvalidSignature();
        ownerNonce = nonce + 1;
    }

    function _domainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    function _recover(
        bytes32 digest,
        bytes calldata signature
    ) private pure returns (address signer) {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (uint256(s) > SECP256K1_HALF_ORDER) revert InvalidSignature();
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();

        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }
}

/// @title Cognisec Dual Bunker Factory
/// @notice Creates distinct AI and DeFi BeaconProxy accounts for Cognisec users.
/// @dev Factory upgrades use UUPS; new and existing BeaconProxy accounts share one upgradeable implementation.
contract CognisecBunkerFactory is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    struct Pair {
        address aiBunker;
        address defiBunker;
    }

    address public provisioner;
    address public billingController;
    address public treasury;
    UpgradeableBeacon public bunkerBeacon;
    mapping(bytes32 pairId => Pair pair) private pairs;
    uint256[40] private __gap;

    event DualBunkersCreated(
        address indexed owner,
        bytes32 indexed userSalt,
        address aiBunker,
        address defiBunker
    );
    event BunkerBeaconChanged(address indexed previousBeacon, address indexed newBeacon);

    error Unauthorized();
    error InvalidConfiguration();
    error PairAlreadyExists();

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address initialOwner,
        address treasury_,
        address beacon_
    ) external initializer {
        if (
            initialOwner == address(0) ||
            treasury_ == address(0) ||
            beacon_ == address(0)
        ) revert InvalidConfiguration();

        __Ownable_init(initialOwner);
        provisioner = initialOwner;
        billingController = initialOwner;
        treasury = treasury_;
        bunkerBeacon = UpgradeableBeacon(beacon_);
    }

    function createDualBunkers(
        address owner_,
        bytes32 userSalt
    ) external returns (address aiBunker, address defiBunker) {
        if (msg.sender != provisioner) revert Unauthorized();
        if (owner_ == address(0) || userSalt == bytes32(0)) {
            revert InvalidConfiguration();
        }

        bytes32 pairId = keccak256(abi.encode(owner_, userSalt));
        if (pairs[pairId].aiBunker != address(0)) revert PairAlreadyExists();

        bytes32 aiSalt = keccak256(abi.encode(pairId, uint8(CognisecBunker.Kind.AI)));
        bytes32 defiSalt = keccak256(abi.encode(pairId, uint8(CognisecBunker.Kind.DEFI)));
        bytes memory aiInitialization = abi.encodeCall(
            CognisecBunker.initialize,
            (owner_, CognisecBunker.Kind.AI, billingController, treasury)
        );
        bytes memory defiInitialization = abi.encodeCall(
            CognisecBunker.initialize,
            (owner_, CognisecBunker.Kind.DEFI, billingController, treasury)
        );

        aiBunker = address(
            new BeaconProxy{salt: aiSalt}(address(bunkerBeacon), aiInitialization)
        );
        defiBunker = address(
            new BeaconProxy{salt: defiSalt}(address(bunkerBeacon), defiInitialization)
        );

        pairs[pairId] = Pair({aiBunker: aiBunker, defiBunker: defiBunker});
        emit DualBunkersCreated(owner_, userSalt, aiBunker, defiBunker);
    }

    function getPair(
        address owner_,
        bytes32 userSalt
    ) external view returns (address aiBunker, address defiBunker) {
        Pair memory pair = pairs[keccak256(abi.encode(owner_, userSalt))];
        return (pair.aiBunker, pair.defiBunker);
    }

    function setBunkerBeacon(address newBeacon) external onlyOwner {
        if (newBeacon == address(0)) revert InvalidConfiguration();
        address previousBeacon = address(bunkerBeacon);
        bunkerBeacon = UpgradeableBeacon(newBeacon);
        emit BunkerBeaconChanged(previousBeacon, newBeacon);
    }

    function predictBunkerAddress(
        address owner_,
        bytes32 userSalt,
        CognisecBunker.Kind kind_
    ) external view returns (address predicted) {
        bytes32 pairId = keccak256(abi.encode(owner_, userSalt));
        bytes32 salt = keccak256(abi.encode(pairId, uint8(kind_)));
        bytes memory initialization = abi.encodeCall(
            CognisecBunker.initialize,
            (owner_, kind_, billingController, treasury)
        );
        bytes memory initCode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(address(bunkerBeacon), initialization)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(initCode))
        );
        predicted = address(uint160(uint256(hash)));
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
