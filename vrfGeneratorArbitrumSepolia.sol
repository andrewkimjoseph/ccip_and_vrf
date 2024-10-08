// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import {VRFConsumerBaseV2Plus} from "@chainlink/contracts/src/v0.8/vrf/dev/VRFConsumerBaseV2Plus.sol";
import {VRFV2PlusClient} from "@chainlink/contracts/src/v0.8/vrf/dev/libraries/VRFV2PlusClient.sol";
import {Client} from "@chainlink/contracts-ccip@1.4.0/src/v0.8/ccip/libraries/Client.sol";
import {CCIPReceiver} from "@chainlink/contracts-ccip@1.4.0/src/v0.8/ccip/applications/CCIPReceiver.sol";
import {IRouterClient} from "@chainlink/contracts-ccip@1.4.0/src/v0.8/ccip/interfaces/IRouterClient.sol";
import {LinkTokenInterface} from "@chainlink/contracts@1.2.0/src/v0.8/shared/interfaces/LinkTokenInterface.sol";

contract vrfGeneratorArbitrumSepolia is CCIPReceiver, VRFConsumerBaseV2Plus {
    uint256 immutable vrfV2SubscriptionId;

    // Chainlink VRF V2 - Coordinator address for Arbitrum Sepolia
    address vrfCoordinatorArbitrumSepolia =
        0x5CE8D5A2BC84beb22a398CCA51996F7930313D61;

    // Chainlink VRF V2 - 50 gwei Key Hash
    bytes32 vrfV2KeyHash =
        0x1770bdc7eec7771f7ba4ffd640f34260d7f095b79c92d34a5b2551d6f6cfd2be;

    event MessageReceived(
        bytes32 indexed messageId, // The unique ID of the message.
        uint64 indexed sourceChainSelector, // The chain selector of the source chain.
        address sender, // The address of the sender from the source chain.
        string text // The text that was received.
    );

    bytes32 public s_lastReceivedMessageId; // Store the last received messageId.
    string public s_lastReceivedText;

    // Custom errors to provide more descriptive revert messages.
    error NotEnoughBalance(uint256 currentBalance, uint256 calculatedFees); // Used to make sure contract has enough balance.

    // Event emitted when a message is sent to another chain.
    event MessageSent(
        bytes32 indexed messageId, // The unique ID of the CCIP message.
        uint64 indexed destinationChainSelector, // The chain selector of the destination chain.
        address receiver, // The address of the receiver on the destination chain.
        uint256 randomNumber, // The text being sent.
        address feeToken, // the token address used to pay CCIP fees.
        uint256 fees // The fees paid for sending the CCIP message.
    );

    // CCIP Router
    IRouterClient private s_router =
        IRouterClient(0x2a9C5afB0d0e4BAb2BCdaE109EC4b0c4Be15a165);

    LinkTokenInterface private s_linkToken =
        LinkTokenInterface(0xb1D4538B4571d411F07960EF2838Ce337FE1E80E);

    constructor()
        VRFConsumerBaseV2Plus(vrfCoordinatorArbitrumSepolia)
        CCIPReceiver(0x2a9C5afB0d0e4BAb2BCdaE109EC4b0c4Be15a165)
    {
        vrfV2SubscriptionId = 70968718472511649343744334382116497041800362490296615430929588015039822016242;
    }

    function _ccipReceive(Client.Any2EVMMessage memory any2EvmMessage)
        internal
        override
    {
        s_lastReceivedMessageId = any2EvmMessage.messageId; // fetch the messageId
        s_lastReceivedText = abi.decode(any2EvmMessage.data, (string));

        generateRandomNumber();

        emit MessageReceived(
            any2EvmMessage.messageId,
            any2EvmMessage.sourceChainSelector, // fetch the source chain identifier (aka selector)
            abi.decode(any2EvmMessage.sender, (address)), // abi-decoding of the sender address,
            abi.decode(any2EvmMessage.data, (string))
        );
    }

    function generateRandomNumber() public {
        uint256 ticketVerificationId = s_vrfCoordinator.requestRandomWords(
            VRFV2PlusClient.RandomWordsRequest({
                keyHash: vrfV2KeyHash,
                subId: vrfV2SubscriptionId,
                requestConfirmations: 1,
                callbackGasLimit: 2500000,
                numWords: 1,
                // Set nativePayment to true to pay for VRF requests with Arbitrum Sepolia ETH instead of LINK
                extraArgs: VRFV2PlusClient._argsToBytes(
                    VRFV2PlusClient.ExtraArgsV1({nativePayment: false})
                )
            })
        );
    }

    // Callback for Chainlink VRF
    function fulfillRandomWords(
        uint256 _requestId,
        uint256[] calldata _randomWords
    ) internal override {
        // Block for verifying events

        uint256 randomNumber = _randomWords[0];
        uint64 _destinationChainSelector = 5224473277236331295;

        sendMessage(
            _destinationChainSelector,
            address(0xec89fAf56A7029eB3069fFA90be0C6461f475bc1), // CHANGE HERE
            randomNumber
        );
    }

    function sendMessage(
        uint64 destinationChainSelector,
        address receiver,
        uint256 randomNumber
    ) public returns (bytes32 messageId) {
        // Create an EVM2AnyMessage struct in memory with necessary information for sending a cross-chain message
        Client.EVM2AnyMessage memory evm2AnyMessage = Client.EVM2AnyMessage({
            receiver: abi.encode(receiver), // ABI-encoded receiver address
            data: abi.encode(randomNumber), // ABI-encoded string
            tokenAmounts: new Client.EVMTokenAmount[](0), // Empty array indicating no tokens are being sent
            extraArgs: Client._argsToBytes(
                // Additional arguments, setting gas limit
                Client.EVMExtraArgsV1({gasLimit: 200_000})
            ),
            // Set the feeToken  address, indicating LINK will be used for fees
            feeToken: address(s_linkToken)
        });

        // Get the fee required to send the message
        uint256 fees = s_router.getFee(
            destinationChainSelector,
            evm2AnyMessage
        );

        if (fees > s_linkToken.balanceOf(address(this)))
            revert NotEnoughBalance(s_linkToken.balanceOf(address(this)), fees);

        // approve the Router to transfer LINK tokens on contract's behalf. It will spend the fees in LINK
        s_linkToken.approve(address(s_router), fees);

        // Send the message through the router and store the returned message ID
        messageId = s_router.ccipSend(destinationChainSelector, evm2AnyMessage);

        // Emit an event with message details
        emit MessageSent(
            messageId,
            destinationChainSelector,
            receiver,
            randomNumber,
            address(s_linkToken),
            fees
        );

        // Return the message ID
        return messageId;
    }
}
