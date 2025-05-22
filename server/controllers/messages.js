const asyncHandler = require("express-async-handler");
const mongoose = require("mongoose");
const Message = require("../models/Message");
const Invite = require("../models/Invite");
const User = require("../models/User");

const MAX_FILE_SIZE = 6 * 1024 * 1024; // 6MB limit - increased for better image quality (slightly higher than client to ensure acceptance)

const sendMessage = asyncHandler(async (req, res) => {
  const senderId = req.user?.userId;
  const { receiver, ciphertext, nonce, headers, expiresAt, type } = req.body;

  console.log("sendMessage - Sender ID from token:", senderId);
  console.log("sendMessage - Request body:", req.body);

  if (!senderId) {
    console.log("Sender ID missing in req.user:", req.user);
    res.status(401);
    throw new Error("Unauthorized: Sender ID missing");
  }

  if (!receiver || !ciphertext || !nonce || !headers || !expiresAt) {
    res.status(400);
    throw new Error(
      "All fields (receiver, ciphertext, nonce, headers, expiresAt) are required"
    );
  }

  if (new Date(expiresAt) <= new Date()) {
    res.status(400);
    throw new Error("expiresAt must be in the future");
  }

  // Validate type field
  if (type && !["text", "image"].includes(type)) {
    res.status(400);
    throw new Error("Invalid message type. Must be 'text' or 'image'");
  }

  // Check message size
  const messageSize = Buffer.from(ciphertext, "base64").length;
  if (messageSize > MAX_FILE_SIZE) {
    res.status(413);
    throw new Error("Message size exceeds the maximum limit of 6MB");
  }

  console.log("Looking up receiver with username:", receiver);
  const recipient = await User.findOne({ username: receiver });
  if (!recipient) {
    console.log("Receiver not found for username:", receiver);
    res.status(404);
    throw new Error("Recipient not found");
  }
  const receiverId = recipient._id;
  console.log("Receiver found:", {
    id: receiverId,
    username: recipient.username,
  });

  console.log("Checking for removed invite between sender and receiver...");
  const removedInvite = await Invite.findOne({
    $or: [
      { sender: senderId, receiver: receiverId, status: "removed" },
      { sender: receiverId, receiver: senderId, status: "removed" },
    ],
  });

  if (removedInvite) {
    console.log("Removed invite found:", removedInvite);
    res.status(403);
    throw new Error("Contact has been removed");
  }

  console.log("Looking up sender with ID:", senderId);
  let sender;
  try {
    sender = await User.findById(new mongoose.Types.ObjectId(senderId)).select(
      "username"
    );
  } catch (error) {
    console.error("Error converting senderId to ObjectId:", error.message);
    res.status(400);
    throw new Error("Invalid sender ID format");
  }

  console.log("Sender query result:", sender);
  if (!sender) {
    console.log("Sender not found in database for ID:", senderId);
    res.status(404);
    throw new Error("Sender not found");
  }
  console.log("Sender found:", { id: sender._id, username: sender.username });

  console.log("Creating new message...");
  const message = await Message.create({
    sender: senderId,
    receiver: receiverId,
    ciphertext,
    nonce,
    headers,
    type: type || "text",
    expiresAt,
    status: "sent",
  });
  console.log("Message created:", message);

  const messageData = {
    _id: message._id,
    sender: { _id: message.sender, username: sender.username },
    receiver: { _id: message.receiver, username: recipient.username },
    ciphertext: message.ciphertext,
    nonce: message.nonce,
    headers: message.headers,
    type: message.type,
    expiresAt: message.expiresAt,
    sentAt: message.sentAt,
    status: message.status,
  };

  console.log("Sending messageData:", messageData);

  const io = req.app.get("io");
  console.log(
    `Emitting newMessage to receiver: ${receiverId} only (not to sender ${senderId})`
  );

  // Only emit to the receiver, not the sender - the sender already has this message locally
  io.to(receiverId.toString()).emit("newMessage", messageData);

  res.status(201).json(messageData);
});

const getMessages = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  console.log("Fetching messages for user:", userId);

  if (!userId) {
    console.log("User ID missing in req.user:", req.user);
    res.status(401);
    throw new Error("Unauthorized: User ID missing");
  }

  // Only fetch messages where the user is the RECEIVER
  // This prevents sending our own sent messages back to us
  const messages = await Message.find({
    receiver: userId, // Only return messages where the user is the receiver
  })
    .sort({ sentAt: 1 })
    .populate("sender", "username")
    .populate("receiver", "username");

  console.log("Messages fetched where user is RECEIVER:", messages.length);
  res.json(messages);
});

const markMessageAsRead = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  console.log("Marking message as read, ID:", req.params.id);

  if (!userId) {
    console.log("User ID missing in req.user:", req.user);
    res.status(401);
    throw new Error("Unauthorized: User ID missing");
  }

  const message = await Message.findById(req.params.id);
  if (!message) {
    console.log(
      `Message ${req.params.id} not found, may have been deleted already`
    );
    // Return 200 instead of 404 to prevent client errors
    return res
      .status(200)
      .json({ message: "Message already deleted or not found" });
  }

  if (!message.receiver.equals(userId)) {
    console.log("Not authorized to mark message as read:", userId);
    res.status(403);
    throw new Error("Not authorized");
  }

  // Update message status to seen
  message.status = "seen";

  // Sensitive data should already be cleared at the delivered stage
  // Just ensure it's still sanitized
  if (message.ciphertext || message.nonce) {
    message.ciphertext = null;
    message.nonce = null;
    message.headers = { sanitized: true };
    message.type = "sanitized";
    console.log(
      `Message ${message._id} sensitive data cleared (was not previously cleared)`
    );
  }

  await message.save();
  console.log("Message marked as seen:", message._id);

  const io = req.app.get("io");
  io.to(message.sender.toString()).emit("messageStatusUpdate", {
    messageId: message._id,
    status: message.status,
  });

  res.status(200).json({ message: "Message marked as seen" });
});

const markMessageAsDelivered = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  console.log("Marking message as delivered, ID:", req.params.id);

  if (!userId) {
    console.log("User ID missing in req.user:", req.user);
    res.status(401);
    throw new Error("Unauthorized: User ID missing");
  }

  const message = await Message.findById(req.params.id);
  if (!message) {
    console.log(
      `Message ${req.params.id} not found, may have been deleted already`
    );
    // Return 200 instead of 404 to prevent client errors
    return res
      .status(200)
      .json({ message: "Message already deleted or not found" });
  }

  if (!message.receiver.equals(userId)) {
    console.log("Not authorized to mark message as delivered:", userId);
    res.status(403);
    throw new Error("Not authorized");
  }

  // Only update status if it's still "sent"
  if (message.status === "sent") {
    // Store original headers
    const originalHeaders = { ...message.headers };

    // Update to delivered AND clear sensitive data immediately
    message.status = "delivered";

    // Clear sensitive data right after delivery
    // Client should have stored the encrypted data in secure storage
    message.ciphertext = null;
    message.nonce = null;
    message.headers = {
      ...originalHeaders,
      sanitized: true,
    };
    message.type = "sanitized";

    await message.save();
    console.log(
      `Message ${message._id} marked as delivered and sensitive data cleared`
    );

    const io = req.app.get("io");
    io.to(message.sender.toString()).emit("messageStatusUpdate", {
      messageId: message._id,
      status: message.status,
    });
  }

  res.status(200).json({ message: "Message marked as delivered" });
});

const acknowledgeMessageStatus = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  const { messageId } = req.params;

  console.log("Acknowledging message status, ID:", messageId);

  if (!userId) {
    console.log("User ID missing in req.user:", req.user);
    res.status(401);
    throw new Error("Unauthorized: User ID missing");
  }

  const message = await Message.findById(messageId);
  if (!message) {
    console.log(
      `Message ${messageId} not found, may have been deleted already`
    );
    // Return 200 instead of 404 to prevent client errors
    return res
      .status(200)
      .json({ message: "Message already deleted or not found" });
  }

  if (!message.sender.equals(userId)) {
    console.log("Not authorized to acknowledge message status:", userId);
    res.status(403);
    throw new Error("Not authorized");
  }

  // If message has been seen by receiver and the sender is acknowledging, delete it
  if (message.status === "seen") {
    console.log(
      `Deleting seen message ${messageId} after sender acknowledgment via API`
    );

    // Send response before deleting to ensure client gets response
    res
      .status(200)
      .json({ message: "Message status acknowledged, scheduled for deletion" });

    // Add a small delay before deleting to ensure the response has been sent
    setTimeout(async () => {
      try {
        // Delete the message from the database
        const deletedMessage = await Message.findByIdAndDelete(messageId);

        if (deletedMessage) {
          console.log(
            `Message ${messageId} deleted after sender acknowledged seen status via API`
          );

          // Notify both sender and receiver that the message has been deleted
          const io = req.app.get("io");
          io.to(message.sender.toString()).emit("message_deleted", {
            messageId,
          });
          io.to(message.receiver.toString()).emit("message_deleted", {
            messageId,
          });
        } else {
          console.log(`Message ${messageId} already deleted or not found`);
        }
      } catch (error) {
        console.error(`Error deleting message ${messageId}:`, error);
      }
    }, 1000); // 1 second delay before deletion
  } else {
    // For non-seen messages, just log the acknowledgment
    console.log(
      `Sender ${userId} acknowledged status for message ${messageId} (status: ${message.status}) via API`
    );
    res.status(200).json({ message: "Message status acknowledged" });
  }
});

const deleteMessage = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  console.log("Delete message requested, ID:", req.params.id);

  // No longer deleting messages, just logging the attempt
  res.status(200).json({
    message: "Messages are now kept forever on the server",
    preserved: true,
  });
});

const deleteMultipleMessages = asyncHandler(async (req, res) => {
  const userId = req.user?.userId;
  const { messageIds } = req.body;

  console.log(
    `Delete multiple messages requested, count: ${messageIds?.length}`
  );

  // No longer deleting messages, just logging the attempt
  res.status(200).json({
    message: "Messages are now kept forever on the server",
    preserved: true,
  });
});

const deleteAllUserMessages = asyncHandler(async (req, res) => {
  const requestingUserId = req.user?.userId;
  const { username } = req.params;

  console.log(`Request to delete all messages for user: ${username}`);

  // No longer deleting messages, just logging the attempt
  res.status(200).json({
    message: "Messages are now kept forever on the server",
    preserved: true,
  });
});

const deleteConversation = asyncHandler(async (req, res) => {
  const requestingUserId = req.user?.userId;
  const { user1, user2 } = req.params;

  console.log(`Request to delete conversation between: ${user1} and ${user2}`);

  // No longer deleting messages, just logging the attempt
  res.status(200).json({
    message: "Messages are now kept forever on the server",
    preserved: true,
  });
});

module.exports = {
  sendMessage,
  getMessages,
  markMessageAsRead,
  markMessageAsDelivered,
  acknowledgeMessageStatus,
  deleteMessage,
  deleteMultipleMessages,
  deleteAllUserMessages,
  deleteConversation,
};
