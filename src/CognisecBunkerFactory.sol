// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

 * Cognisec is a privacy-focused platform for secure AI and digital finance.
 * Learn more at https://cognisec.org.
 */

/// @title Cognisec Bunker
/// @notice A user-owned account with separate AI-billing and DeFi execution policies.
/// @dev This source is a draft and must be independently reviewed before mainnet use.
contract CognisecBunker {
    enum Kind {
        AI,
        DEFI
    }

    struct Reservation {
        address asset;
        uint256 amount;
        uint256 day;
        uint8 state; // 0 unused, 1 reserved, 2 settled, 3 released
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
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes4 private constant BALANCE_OF_SELECTOR = 0x70a08231;
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb;

    address public immutable owner;
    Kind public immutable kind;
    address public immutable billingController;
    address public immutable treasury;
    uint256 public ownerNonce;

    mapping(address asset => uint256 amount) public reservedAmount;
    mapping(address asset => uint256 amount) public dailyLimit;
    mapping(address asset => mapping(uint256 day => uint256 amount)) public spentByDay;
    mapping(bytes32 reservationId => Reservation reservation) public reservations;

    uint256 private entered = 1;

    event Deposited(address indexed asset, address indexed sender, uint256 amount);
    event Withdrawn(address indexed asset, address indexed recipient, uint256 amount);
    event DailyLimitUpdated(address indexed asset, uint256 limit);
    event Executed(address indexed target, uint256 value, bytes32 dataHash);
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

    constructor(
        address owner_,
        Kind kind_,
        address billingController_,
        address treasury_
    ) {
        if (owner_ == address(0)) revert InvalidConfiguration();
        if (billingController_ == address(0) || treasury_ == address(0)) {
            revert InvalidConfiguration();
        }
        owner = owner_;
        kind = kind_;
        billingController = billingController_;
        treasury = treasury_;
    }

    receive() external payable {
        emit Deposited(address(0), msg.sender, msg.value);
    }

    /// @notice Return the balance that is not committed to an AI usage reservation.
    function availableBalance(address asset) public view returns (uint256) {
        uint256 balance = _balanceOf(asset);
        uint256 reserved = reservedAmount[asset];
        return balance > reserved ? balance - reserved : 0;
    }

    /// @notice Withdraw unreserved assets directly as the wallet owner.
    function withdraw(
        address asset,
        address payable recipient,
        uint256 amount
    ) external onlyOwner nonReentrant {
        _withdraw(asset, recipient, amount);
    }

    /// @notice Withdraw unreserved assets using an owner signature; any relayer may submit it.
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

    /// @notice Set an AI usage limit for a specific token or native ETH (asset address zero).
    function setDailyLimit(address asset, uint256 limit) external onlyOwner {
        _setDailyLimit(asset, limit);
    }

    /// @notice Set an AI usage limit using an owner signature; any relayer may submit it.
    function setDailyLimitWithSignature(
        address asset,
        uint256 limit,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (kind != Kind.AI) revert WrongBunkerKind();
        bytes32 structHash = keccak256(
            abi.encode(DAILY_LIMIT_TYPEHASH, asset, limit, nonce, deadline)
        );
        _consumeOwnerSignature(structHash, nonce, deadline, signature);
        _setDailyLimit(asset, limit);
    }

    /// @notice Execute a DeFi operation authorized by the owner; any relayer may submit it.
    function executeWithSignature(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant returns (bytes memory result) {
        if (kind != Kind.DEFI) revert WrongBunkerKind();
        if (target == address(0)) revert InvalidConfiguration();

        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_TYPEHASH,
                target,
                value,
                keccak256(data),
                nonce,
                deadline
            )
        );
        _consumeOwnerSignature(structHash, nonce, deadline, signature);

        bool success;
        (success, result) = target.call{value: value}(data);
        if (!success) revert ExternalCallFailed(result);
        emit Executed(target, value, keccak256(data));
    }

    /// @notice Reserve available AI Bunker funds for a verified service usage record.
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

    /// @notice Settle a reservation to the fixed treasury; the billing controller cannot choose a recipient.
    function settleUsage(
        bytes32 reservationId
    ) external onlyBillingController nonReentrant {
        Reservation storage reservation = reservations[reservationId];
        if (reservation.state != 1) revert InvalidReservation();

        address asset = reservation.asset;
        uint256 amount = reservation.amount;
        reservation.state = 2;
        reservedAmount[asset] -= amount;
        _transferAsset(asset, payable(treasury), amount);
        emit UsageSettled(reservationId, asset, amount);
    }

    /// @notice Release an unused reservation and restore that day's spending allowance.
    function releaseUsage(
        bytes32 reservationId
    ) external onlyBillingController {
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
        if (availableBalance(asset) < amount) revert InsufficientAvailableBalance();
        _transferAsset(asset, recipient, amount);
        emit Withdrawn(asset, recipient, amount);
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
            abi.encode(
                DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                block.chainid,
                address(this)
            )
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
/// @notice Deploys distinct AI and DeFi accounts for a server-provisioned user owner.
/// @dev The deployer is the only account allowed to create pairs. No user owner key is held by this factory.
contract CognisecBunkerFactory {
    struct Pair {
        address aiBunker;
        address defiBunker;
    }

    address public immutable provisioner;
    address public immutable billingController;
    address public immutable treasury;
    mapping(bytes32 pairId => Pair pair) private pairs;

    event DualBunkersCreated(
        address indexed owner,
        bytes32 indexed userSalt,
        address aiBunker,
        address defiBunker
    );

    error Unauthorized();
    error InvalidConfiguration();
    error PairAlreadyExists();

    constructor(address billingController_, address treasury_) {
        if (billingController_ == address(0) || treasury_ == address(0)) {
            revert InvalidConfiguration();
        }
        provisioner = msg.sender;
        billingController = billingController_;
        treasury = treasury_;
    }

    function createDualBunkers(
        address owner,
        bytes32 userSalt
    ) external returns (address aiBunker, address defiBunker) {
        if (msg.sender != provisioner) revert Unauthorized();
        if (owner == address(0) || userSalt == bytes32(0)) {
            revert InvalidConfiguration();
        }

        bytes32 pairId = keccak256(abi.encode(owner, userSalt));
        if (pairs[pairId].aiBunker != address(0)) revert PairAlreadyExists();

        bytes32 aiSalt = keccak256(abi.encode(pairId, uint8(CognisecBunker.Kind.AI)));
        bytes32 defiSalt = keccak256(abi.encode(pairId, uint8(CognisecBunker.Kind.DEFI)));

        aiBunker = address(
            new CognisecBunker{salt: aiSalt}(
                owner,
                CognisecBunker.Kind.AI,
                billingController,
                treasury
            )
        );
        defiBunker = address(
            new CognisecBunker{salt: defiSalt}(
                owner,
                CognisecBunker.Kind.DEFI,
                billingController,
                treasury
            )
        );

        pairs[pairId] = Pair({aiBunker: aiBunker, defiBunker: defiBunker});
        emit DualBunkersCreated(owner, userSalt, aiBunker, defiBunker);
    }

    function getPair(
        address owner,
        bytes32 userSalt
    ) external view returns (address aiBunker, address defiBunker) {
        Pair memory pair = pairs[keccak256(abi.encode(owner, userSalt))];
        return (pair.aiBunker, pair.defiBunker);
    }

    function predictBunkerAddress(
        address owner,
        bytes32 userSalt,
        CognisecBunker.Kind kind
    ) external view returns (address predicted) {
        bytes32 pairId = keccak256(abi.encode(owner, userSalt));
        bytes32 salt = keccak256(abi.encode(pairId, uint8(kind)));
        bytes memory initCode = abi.encodePacked(
            type(CognisecBunker).creationCode,
            abi.encode(owner, kind, billingController, treasury)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(initCode))
        );
        predicted = address(uint160(uint256(hash)));
    }
}
