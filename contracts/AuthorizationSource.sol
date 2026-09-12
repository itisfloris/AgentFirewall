// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract AuthorizationSource {
    bytes32 public constant AUTHORIZATION_COMMITMENT_DOMAIN =
        keccak256("AgentFirewall.Authorization.v3");

    bytes32 public constant AUTHORIZATION_ID_DOMAIN =
        keccak256("AgentFirewall.AuthorizationId.v1");

    uint8 public constant ACTION_NATIVE_TRANSFER = 1;
    uint8 public constant ACTION_ERC20_APPROVE = 2;
    uint8 public constant ACTION_ERC20_TRANSFER = 3;
    uint8 public constant ACTION_ERC20_TRANSFER_FROM = 4;
    uint8 public constant ACTION_NFT_SET_APPROVAL_FOR_ALL = 5;

    bytes4 private constant ERC20_APPROVE_SELECTOR =
        bytes4(keccak256("approve(address,uint256)"));
    bytes4 private constant ERC20_TRANSFER_SELECTOR =
        bytes4(keccak256("transfer(address,uint256)"));
    bytes4 private constant ERC20_TRANSFER_FROM_SELECTOR =
        bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 private constant NFT_SET_APPROVAL_FOR_ALL_SELECTOR =
        bytes4(keccak256("setApprovalForAll(address,bool)"));

    struct Authorization {
        uint256 executionChainId;
        address sender;
        uint256 executionNonce;
        uint64 validUntil;
        uint8 actionCode;
        address target;
        bytes32 targetCodeHash;
        address asset;
        address counterpartyA;
        address counterpartyB;
        uint256 amountOrFlag;
    }

    mapping(address => uint256) public nextNonce;

    event AuthorizationPublished(
        bytes32 indexed authorizationId,
        bytes32 indexed commitment,
        address indexed sender,
        uint256 nonce,
        uint256 executionChainId,
        uint256 executionNonce,
        uint64 validUntil,
        uint8 actionCode,
        address target,
        bytes32 targetCodeHash,
        address asset,
        address counterpartyA,
        address counterpartyB,
        uint256 amountOrFlag,
        bytes32 callDataHash,
        uint256 nativeValueWei
    );

    error SenderMustBeCaller(address sender, address caller);
    error UnsupportedAction(uint8 actionCode);
    error InvalidAuthorizationShape();
    error AuthorizationAlreadyExpired(uint64 validUntil, uint256 currentTime);

    function publishAuthorization(
        Authorization calldata authorization
    ) external returns (bytes32 authorizationId, bytes32 commitment) {
        if (authorization.sender != msg.sender) {
            revert SenderMustBeCaller(authorization.sender, msg.sender);
        }

        _validateShape(authorization);

        if (authorization.validUntil <= block.timestamp) {
            revert AuthorizationAlreadyExpired(
                authorization.validUntil,
                block.timestamp
            );
        }

        (bytes32 callDataHash, uint256 nativeValueWei) =
            computeExecutionBinding(authorization);

        commitment = _computeCommitment(
            authorization,
            callDataHash,
            nativeValueWei
        );

        uint256 nonce = nextNonce[msg.sender];
        nextNonce[msg.sender] = nonce + 1;

        authorizationId = keccak256(
            abi.encode(
                AUTHORIZATION_ID_DOMAIN,
                block.chainid,
                address(this),
                msg.sender,
                nonce,
                authorization.validUntil,
                commitment
            )
        );

        emit AuthorizationPublished(
            authorizationId,
            commitment,
            authorization.sender,
            nonce,
            authorization.executionChainId,
            authorization.executionNonce,
            authorization.validUntil,
            authorization.actionCode,
            authorization.target,
            authorization.targetCodeHash,
            authorization.asset,
            authorization.counterpartyA,
            authorization.counterpartyB,
            authorization.amountOrFlag,
            callDataHash,
            nativeValueWei
        );
    }

    function computeCommitment(
        Authorization calldata authorization
    ) public pure returns (bytes32) {
        _validateShape(authorization);

        (bytes32 callDataHash, uint256 nativeValueWei) =
            computeExecutionBinding(authorization);

        return _computeCommitment(
            authorization,
            callDataHash,
            nativeValueWei
        );
    }

    function computeExecutionBinding(
        Authorization calldata authorization
    ) public pure returns (bytes32 callDataHash, uint256 nativeValueWei) {
        uint8 action = authorization.actionCode;

        if (action == ACTION_NATIVE_TRANSFER) {
            return (
                keccak256(bytes("")),
                authorization.amountOrFlag
            );
        }

        if (action == ACTION_ERC20_APPROVE) {
            return (
                keccak256(
                    abi.encodeWithSelector(
                        ERC20_APPROVE_SELECTOR,
                        authorization.counterpartyA,
                        authorization.amountOrFlag
                    )
                ),
                0
            );
        }

        if (action == ACTION_ERC20_TRANSFER) {
            return (
                keccak256(
                    abi.encodeWithSelector(
                        ERC20_TRANSFER_SELECTOR,
                        authorization.counterpartyA,
                        authorization.amountOrFlag
                    )
                ),
                0
            );
        }

        if (action == ACTION_ERC20_TRANSFER_FROM) {
            return (
                keccak256(
                    abi.encodeWithSelector(
                        ERC20_TRANSFER_FROM_SELECTOR,
                        authorization.counterpartyA,
                        authorization.counterpartyB,
                        authorization.amountOrFlag
                    )
                ),
                0
            );
        }

        if (action == ACTION_NFT_SET_APPROVAL_FOR_ALL) {
            return (
                keccak256(
                    abi.encodeWithSelector(
                        NFT_SET_APPROVAL_FOR_ALL_SELECTOR,
                        authorization.counterpartyA,
                        authorization.amountOrFlag == 1
                    )
                ),
                0
            );
        }

        revert UnsupportedAction(action);
    }

    function _computeCommitment(
        Authorization calldata authorization,
        bytes32 callDataHash,
        uint256 nativeValueWei
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                AUTHORIZATION_COMMITMENT_DOMAIN,
                authorization.executionChainId,
                authorization.sender,
                authorization.executionNonce,
                authorization.validUntil,
                authorization.actionCode,
                authorization.target,
                authorization.targetCodeHash,
                authorization.asset,
                authorization.counterpartyA,
                authorization.counterpartyB,
                authorization.amountOrFlag,
                callDataHash,
                nativeValueWei
            )
        );
    }

    function _validateShape(
        Authorization calldata authorization
    ) private pure {
        uint8 action = authorization.actionCode;

        if (
            action < ACTION_NATIVE_TRANSFER ||
            action > ACTION_NFT_SET_APPROVAL_FOR_ALL
        ) {
            revert UnsupportedAction(action);
        }

        if (
            authorization.target == address(0) ||
            authorization.targetCodeHash == bytes32(0) ||
            authorization.validUntil == 0
        ) {
            revert InvalidAuthorizationShape();
        }

        if (action == ACTION_NATIVE_TRANSFER) {
            if (
                authorization.asset != address(0) ||
                authorization.counterpartyA != authorization.target ||
                authorization.counterpartyB != address(0)
            ) {
                revert InvalidAuthorizationShape();
            }
            return;
        }

        if (authorization.asset != authorization.target) {
            revert InvalidAuthorizationShape();
        }

        if (
            action == ACTION_ERC20_APPROVE ||
            action == ACTION_ERC20_TRANSFER
        ) {
            if (
                authorization.counterpartyA == address(0) ||
                authorization.counterpartyB != address(0)
            ) {
                revert InvalidAuthorizationShape();
            }
            return;
        }

        if (action == ACTION_ERC20_TRANSFER_FROM) {
            if (
                authorization.counterpartyA == address(0) ||
                authorization.counterpartyB == address(0)
            ) {
                revert InvalidAuthorizationShape();
            }
            return;
        }

        if (
            authorization.counterpartyA == address(0) ||
            authorization.counterpartyB != address(0) ||
            authorization.amountOrFlag > 1
        ) {
            revert InvalidAuthorizationShape();
        }
    }
}
