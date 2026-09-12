// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EvmV1Decoder} from "@gluwa/asc-contracts/contracts/common/EvmV1Decoder.sol";

interface IAgentFirewallNativeQueryVerifier {
    struct MerkleProofEntry {
        bytes32 hash;
        bool isLeft;
    }

    struct MerkleProof {
        bytes32 root;
        MerkleProofEntry[] siblings;
    }

    struct ContinuityProof {
        bytes32 lowerEndpointDigest;
        bytes32[] roots;
    }

    function verifyAndEmit(
        uint64 chainKey,
        uint64 height,
        bytes calldata encodedTransaction,
        MerkleProof calldata merkleProof,
        ContinuityProof calldata continuityProof
    ) external returns (bool);
}

contract VerifiedAuthorizationRegistry {
    address public constant BLOCK_PROVER =
        0x0000000000000000000000000000000000000FD2;

    IAgentFirewallNativeQueryVerifier public constant VERIFIER =
        IAgentFirewallNativeQueryVerifier(BLOCK_PROVER);

    bytes32 public constant AUTHORIZATION_COMMITMENT_DOMAIN =
        keccak256("AgentFirewall.Authorization.v3");

    bytes32 public constant AUTHORIZATION_ID_DOMAIN =
        keccak256("AgentFirewall.AuthorizationId.v1");

    bytes32 public constant AUTHORIZATION_PUBLISHED_TOPIC =
        keccak256(
            "AuthorizationPublished(bytes32,bytes32,address,uint256,uint256,uint256,uint64,uint8,address,bytes32,address,address,address,uint256,bytes32,uint256)"
        );

    uint8 private constant ACTION_NATIVE_TRANSFER = 1;
    uint8 private constant ACTION_ERC20_APPROVE = 2;
    uint8 private constant ACTION_ERC20_TRANSFER = 3;
    uint8 private constant ACTION_ERC20_TRANSFER_FROM = 4;
    uint8 private constant ACTION_NFT_SET_APPROVAL_FOR_ALL = 5;

    bytes4 private constant ERC20_APPROVE_SELECTOR =
        bytes4(keccak256("approve(address,uint256)"));
    bytes4 private constant ERC20_TRANSFER_SELECTOR =
        bytes4(keccak256("transfer(address,uint256)"));
    bytes4 private constant ERC20_TRANSFER_FROM_SELECTOR =
        bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 private constant NFT_SET_APPROVAL_FOR_ALL_SELECTOR =
        bytes4(keccak256("setApprovalForAll(address,bool)"));

    uint64 public immutable trustedSourceChainKey;
    uint256 public immutable trustedSourceChainId;
    address public immutable trustedAuthorizationSource;

    struct VerifiedAuthorization {
        bytes32 commitment;
        uint64 sourceChainKey;
        uint64 sourceBlockNumber;
        uint64 transactionIndex;
        uint64 validUntil;
        address sourceSender;
        bytes32 transactionKey;
        bytes32 provenTransactionHash;
        bool verified;
    }

    struct AuthorizationEventData {
        uint256 nonce;
        uint256 executionChainId;
        uint256 executionNonce;
        uint64 validUntil;
        uint8 actionCode;
        address target;
        bytes32 targetCodeHash;
        address asset;
        address counterpartyA;
        address counterpartyB;
        uint256 amountOrFlag;
        bytes32 callDataHash;
        uint256 nativeValueWei;
    }

    mapping(bytes32 => VerifiedAuthorization) private authorizations;
    mapping(bytes32 => bool) public processedTransactions;

    event VerifiedAuthorizationRecorded(
        bytes32 indexed authorizationId,
        bytes32 indexed commitment,
        address indexed sourceSender,
        uint64 sourceChainKey,
        uint64 sourceBlockNumber,
        uint64 transactionIndex,
        uint64 validUntil,
        bytes32 transactionKey,
        bytes32 provenTransactionHash
    );

    error WrongSourceChain(uint64 expected, uint64 actual);
    error TransactionAlreadyProcessed(bytes32 transactionKey);
    error AuthorizationAlreadyRecorded(bytes32 authorizationId);
    error MerklePathTooDeep(uint256 length);
    error VerificationFailed();
    error SourceTransactionFailed(uint256 receiptStatus);
    error TrustedAuthorizationEventCount(uint256 count);
    error InvalidAuthorizationEventTopics(uint256 count);
    error AuthorizationExpired(uint64 validUntil, uint256 currentTime);
    error InvalidAuthorizationShape();
    error UnsupportedAction(uint8 actionCode);
    error EventCommitmentMismatch(bytes32 emitted, bytes32 recomputed);
    error EventExecutionBindingMismatch();
    error AuthorizationIdMismatch(bytes32 emitted, bytes32 recomputed);

    constructor(
        uint64 sourceChainKey,
        uint256 sourceChainId,
        address authorizationSource
    ) {
        if (
            sourceChainKey == 0 ||
            authorizationSource == address(0) ||
            sourceChainId == 0
        ) {
            revert InvalidAuthorizationShape();
        }

        trustedSourceChainKey = sourceChainKey;
        trustedSourceChainId = sourceChainId;
        trustedAuthorizationSource = authorizationSource;
    }

    function submitVerifiedAuthorization(
        uint64 chainKey,
        uint64 blockHeight,
        bytes calldata encodedTransaction,
        bytes32 merkleRoot,
        IAgentFirewallNativeQueryVerifier.MerkleProofEntry[] calldata siblings,
        bytes32 lowerEndpointDigest,
        bytes32[] calldata continuityRoots
    ) external returns (bytes32 authorizationId) {
        if (chainKey != trustedSourceChainKey) {
            revert WrongSourceChain(trustedSourceChainKey, chainKey);
        }

        uint64 transactionIndex = _calculateTransactionIndex(siblings);
        bytes32 transactionKey = computeTransactionKey(
            chainKey,
            blockHeight,
            transactionIndex
        );

        if (processedTransactions[transactionKey]) {
            revert TransactionAlreadyProcessed(transactionKey);
        }

        processedTransactions[transactionKey] = true;

        IAgentFirewallNativeQueryVerifier.MerkleProof memory merkleProof =
            IAgentFirewallNativeQueryVerifier.MerkleProof({
                root: merkleRoot,
                siblings: siblings
            });

        IAgentFirewallNativeQueryVerifier.ContinuityProof memory continuityProof =
            IAgentFirewallNativeQueryVerifier.ContinuityProof({
                lowerEndpointDigest: lowerEndpointDigest,
                roots: continuityRoots
            });

        bool verified = VERIFIER.verifyAndEmit(
            chainKey,
            blockHeight,
            encodedTransaction,
            merkleProof,
            continuityProof
        );

        if (!verified) {
            revert VerificationFailed();
        }

        EvmV1Decoder.ReceiptFields memory receipt =
            EvmV1Decoder.decodeReceiptFields(encodedTransaction);

        if (receipt.receiptStatus != 1) {
            revert SourceTransactionFailed(receipt.receiptStatus);
        }

        EvmV1Decoder.LogEntry[] memory matchingLogs =
            EvmV1Decoder.getLogsByEventSignature(
                receipt,
                AUTHORIZATION_PUBLISHED_TOPIC
            );

        EvmV1Decoder.LogEntry memory trustedLog;
        uint256 trustedCount = 0;

        for (uint256 i = 0; i < matchingLogs.length; ++i) {
            if (matchingLogs[i].address_ == trustedAuthorizationSource) {
                trustedLog = matchingLogs[i];
                ++trustedCount;
            }
        }

        if (trustedCount != 1) {
            revert TrustedAuthorizationEventCount(trustedCount);
        }

        if (trustedLog.topics.length != 4) {
            revert InvalidAuthorizationEventTopics(trustedLog.topics.length);
        }

        authorizationId = trustedLog.topics[1];
        bytes32 emittedCommitment = trustedLog.topics[2];
        address sourceSender = address(uint160(uint256(trustedLog.topics[3])));

        if (sourceSender == address(0)) {
            revert InvalidAuthorizationShape();
        }

        AuthorizationEventData memory eventData = abi.decode(
            trustedLog.data,
            (AuthorizationEventData)
        );

        _validateShape(eventData);

        if (eventData.validUntil <= block.timestamp) {
            revert AuthorizationExpired(eventData.validUntil, block.timestamp);
        }

        (bytes32 expectedCallDataHash, uint256 expectedNativeValueWei) =
            _computeExecutionBinding(eventData);

        if (
            eventData.callDataHash != expectedCallDataHash ||
            eventData.nativeValueWei != expectedNativeValueWei
        ) {
            revert EventExecutionBindingMismatch();
        }

        bytes32 recomputedCommitment = _computeCommitment(
            eventData,
            sourceSender
        );

        if (recomputedCommitment != emittedCommitment) {
            revert EventCommitmentMismatch(
                emittedCommitment,
                recomputedCommitment
            );
        }

        bytes32 recomputedAuthorizationId = keccak256(
            abi.encode(
                AUTHORIZATION_ID_DOMAIN,
                trustedSourceChainId,
                trustedAuthorizationSource,
                sourceSender,
                eventData.nonce,
                eventData.validUntil,
                emittedCommitment
            )
        );

        if (recomputedAuthorizationId != authorizationId) {
            revert AuthorizationIdMismatch(
                authorizationId,
                recomputedAuthorizationId
            );
        }

        if (authorizations[authorizationId].verified) {
            revert AuthorizationAlreadyRecorded(authorizationId);
        }

        bytes32 provenTransactionHash =
            keccak256(encodedTransaction);

        authorizations[authorizationId] = VerifiedAuthorization({
            commitment: emittedCommitment,
            sourceChainKey: chainKey,
            sourceBlockNumber: blockHeight,
            transactionIndex: transactionIndex,
            validUntil: eventData.validUntil,
            sourceSender: sourceSender,
            transactionKey: transactionKey,
            provenTransactionHash: provenTransactionHash,
            verified: true
        });

        emit VerifiedAuthorizationRecorded(
            authorizationId,
            emittedCommitment,
            sourceSender,
            chainKey,
            blockHeight,
            transactionIndex,
            eventData.validUntil,
            transactionKey,
            provenTransactionHash
        );
    }

    function getAuthorization(
        bytes32 authorizationId
    )
        external
        view
        returns (
            bytes32 commitment,
            uint64 sourceChainKey,
            uint64 sourceBlockNumber,
            uint64 transactionIndex,
            uint64 validUntil,
            bool verified
        )
    {
        VerifiedAuthorization memory record = authorizations[authorizationId];

        return (
            record.commitment,
            record.sourceChainKey,
            record.sourceBlockNumber,
            record.transactionIndex,
            record.validUntil,
            record.verified
        );
    }

    function getAuthorizationEvidence(
        bytes32 authorizationId
    )
        external
        view
        returns (
            bytes32 commitment,
            uint64 sourceChainKey,
            uint64 sourceBlockNumber,
            uint64 transactionIndex,
            uint64 validUntil,
            address sourceSender,
            bytes32 transactionKey,
            bytes32 provenTransactionHash,
            bool verified
        )
    {
        VerifiedAuthorization memory record = authorizations[authorizationId];

        return (
            record.commitment,
            record.sourceChainKey,
            record.sourceBlockNumber,
            record.transactionIndex,
            record.validUntil,
            record.sourceSender,
            record.transactionKey,
            record.provenTransactionHash,
            record.verified
        );
    }

    function computeTransactionKey(
        uint64 chainKey,
        uint64 blockHeight,
        uint64 transactionIndex
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(chainKey, blockHeight, transactionIndex)
        );
    }

    function _computeCommitment(
        AuthorizationEventData memory eventData,
        address sourceSender
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                AUTHORIZATION_COMMITMENT_DOMAIN,
                eventData.executionChainId,
                sourceSender,
                eventData.executionNonce,
                eventData.validUntil,
                eventData.actionCode,
                eventData.target,
                eventData.targetCodeHash,
                eventData.asset,
                eventData.counterpartyA,
                eventData.counterpartyB,
                eventData.amountOrFlag,
                eventData.callDataHash,
                eventData.nativeValueWei
            )
        );
    }

    function _computeExecutionBinding(
        AuthorizationEventData memory eventData
    ) private pure returns (bytes32 callDataHash, uint256 nativeValueWei) {
        uint8 action = eventData.actionCode;

        if (action == ACTION_NATIVE_TRANSFER) {
            return (keccak256(bytes("")), eventData.amountOrFlag);
        }

        if (action == ACTION_ERC20_APPROVE) {
            return (
                keccak256(
                    abi.encodeWithSelector(
                        ERC20_APPROVE_SELECTOR,
                        eventData.counterpartyA,
                        eventData.amountOrFlag
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
                        eventData.counterpartyA,
                        eventData.amountOrFlag
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
                        eventData.counterpartyA,
                        eventData.counterpartyB,
                        eventData.amountOrFlag
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
                        eventData.counterpartyA,
                        eventData.amountOrFlag == 1
                    )
                ),
                0
            );
        }

        revert UnsupportedAction(action);
    }

    function _validateShape(
        AuthorizationEventData memory eventData
    ) private pure {
        uint8 action = eventData.actionCode;

        if (
            action < ACTION_NATIVE_TRANSFER ||
            action > ACTION_NFT_SET_APPROVAL_FOR_ALL
        ) {
            revert UnsupportedAction(action);
        }

        if (
            eventData.target == address(0) ||
            eventData.targetCodeHash == bytes32(0) ||
            eventData.validUntil == 0
        ) {
            revert InvalidAuthorizationShape();
        }

        if (action == ACTION_NATIVE_TRANSFER) {
            if (
                eventData.asset != address(0) ||
                eventData.counterpartyA != eventData.target ||
                eventData.counterpartyB != address(0)
            ) {
                revert InvalidAuthorizationShape();
            }
            return;
        }

        if (eventData.asset != eventData.target) {
            revert InvalidAuthorizationShape();
        }

        if (
            action == ACTION_ERC20_APPROVE ||
            action == ACTION_ERC20_TRANSFER
        ) {
            if (
                eventData.counterpartyA == address(0) ||
                eventData.counterpartyB != address(0)
            ) {
                revert InvalidAuthorizationShape();
            }
            return;
        }

        if (action == ACTION_ERC20_TRANSFER_FROM) {
            if (
                eventData.counterpartyA == address(0) ||
                eventData.counterpartyB == address(0)
            ) {
                revert InvalidAuthorizationShape();
            }
            return;
        }

        if (
            eventData.counterpartyA == address(0) ||
            eventData.counterpartyB != address(0) ||
            eventData.amountOrFlag > 1
        ) {
            revert InvalidAuthorizationShape();
        }
    }

    function _calculateTransactionIndex(
        IAgentFirewallNativeQueryVerifier.MerkleProofEntry[] calldata siblings
    ) private pure returns (uint64 transactionIndex) {
        uint256 length = siblings.length;
        if (length > 64) {
            revert MerklePathTooDeep(length);
        }

        uint64 index = 0;
        for (uint256 i = 0; i < length; ++i) {
            if (siblings[i].isLeft) {
                index |= uint64(1) << uint64(i);
            }
        }

        return index;
    }
}
