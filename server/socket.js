const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const User = require("./models/User");
const Message = require("./models/Message");
const axios = require("axios");
const mongoose = require("mongoose");

const setupSocket = (server) => {
  const io = new Server(server, {
    cors: {
      origin: "https://192.168.1.85:3000",
      methods: ["GET", "POST", "PATCH", "DELETE"],
      credentials: true,
    },
  });

  const userSockets = new Map();
  const userOnlineStatus = new Map(); // Track online status of users
  io.userCurrentChat = new Map(); // Make it accessible via io object

  io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Authentication error"));

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);
      if (!user || user.deviceId !== decoded.deviceId) {
        return next(new Error("Authentication failed"));
      }
      socket.userId = decoded.userId;
      next();
    } catch (error) {
      next(new Error("Invalid token"));
    }
  });

  io.on("connection", (socket) => {
    console.log(`User connected: ${socket.id}`);

    socket.on("register", async (userId) => {
      if (userId !== socket.userId) {
        console.warn(
          `Unauthorized register attempt: ${userId} != ${socket.userId}`
        );
        return;
      }

      // Remove any existing socket for this user
      for (let [existingUserId, socketId] of userSockets.entries()) {
        if (existingUserId === userId && socketId !== socket.id) {
          userSockets.delete(existingUserId);
          console.log(`Removed stale socket for user ${userId}`);
          break;
        }
      }

      // Set the user as online
      userSockets.set(userId, socket.id);
      userOnlineStatus.set(userId, true);
      socket.join(userId);

      // Log registration with detailed online status information
      console.log(
        `User ${userId} registered on socket ${socket.id}, joined room ${userId}`
      );

      // Print all online users for better debugging
      const onlineUsers = Array.from(userOnlineStatus.entries())
        .filter(([_, isOnline]) => isOnline)
        .map(([id, _]) => id);

      console.log(
        `🟢 Current online users (${onlineUsers.length}): ${onlineUsers.join(
          ", "
        )}`
      );

      // Immediately mark all pending messages as delivered when user connects
      try {
        const user = await User.findById(userId).select("username");
        if (user) {
          console.log(`🟢 User ${user.username} (${userId}) is now ONLINE`);

          // Immediately mark any pending messages as delivered
          const deliveredCount = await markPendingMessagesAsDelivered(userId);

          if (deliveredCount > 0) {
            console.log(
              `✅ Marked ${deliveredCount} messages as delivered immediately on connect for ${user.username}`
            );
          } else {
            console.log(
              `No pending messages for ${user.username} to mark as delivered`
            );
          }
        }
      } catch (error) {
        console.error("Error processing user connection:", error);
      }
    });

    // Handle user actively viewing a specific chat
    socket.on("viewing_chat", async ({ contactId }) => {
      if (!socket.userId) return;

      console.log(`User ${socket.userId} is viewing chat with ${contactId}`);

      // Update which chat this user is viewing
      io.userCurrentChat.set(socket.userId, contactId);

      // First, get the ObjectId of the contact if contactId is a username
      let contactObjectId;

      // Check if contactId is already a valid ObjectId
      if (mongoose.Types.ObjectId.isValid(contactId)) {
        contactObjectId = contactId;
      } else {
        // Look up the user by username
        const contact = await User.findOne({ username: contactId });
        if (!contact) {
          console.log(`Contact not found: ${contactId}`);
          return;
        }
        contactObjectId = contact._id;
      }

      // FIRST PART: Mark messages as delivered regardless of whether sender is viewing chat
      try {
        const messages = await Message.find({
          receiver: socket.userId,
          sender: contactObjectId,
          status: "sent",
        });

        // Update status to delivered AND clear sensitive data for all these messages
        // Client should have already stored the encrypted data in secure storage
        for (const message of messages) {
          message.status = "delivered";

          // Clear sensitive data right after delivery
          message.ciphertext = null;
          message.nonce = null;
          message.headers = { sanitized: true };
          message.type = "sanitized";

          await message.save();

          // Notify sender about delivery
          io.to(message.sender.toString()).emit("messageStatusUpdate", {
            messageId: message._id,
            status: "delivered",
          });
        }

        if (messages.length > 0) {
          console.log(
            `Marked ${messages.length} messages as delivered for user ${socket.userId} and cleared sensitive data`
          );
        }
      } catch (error) {
        console.error("Error updating message delivery status:", error);
      }

      // SECOND PART: Check if there are any messages the current user sent that have been seen
      // but not yet acknowledged. This ensures the sender gets updated when they return to the chat.
      try {
        // Find messages that this user (socket.userId) sent to the contact
        // that have been marked as seen but not yet acknowledged by the sender
        const seenMessages = await Message.find({
          sender: socket.userId,
          receiver: contactObjectId,
          status: "seen",
        });

        if (seenMessages.length > 0) {
          console.log(
            `Found ${seenMessages.length} seen messages to notify sender ${socket.userId} about`
          );

          // Notify the sender (current user) about these seen messages
          for (const message of seenMessages) {
            io.to(socket.userId.toString()).emit("messageStatusUpdate", {
              messageId: message._id,
              status: "seen",
            });
            console.log(
              `Notified sender ${socket.userId} that message ${message._id} was seen`
            );
          }
        }
      } catch (error) {
        console.error("Error checking for seen messages:", error);
      }
    });

    socket.on("leaving_chat", () => {
      if (!socket.userId) return;

      // Remove from userCurrentChat but ENSURE user remains marked as online
      io.userCurrentChat.delete(socket.userId);
      userOnlineStatus.set(socket.userId, true); // Explicitly set to online

      console.log(
        `User ${socket.userId} left their current chat but is still online`
      );

      // Print current online users after leaving chat
      const onlineCount = Array.from(userOnlineStatus.values()).filter(
        (status) => status
      ).length;
      console.log(
        `Current online users (${onlineCount}):`,
        Array.from(userOnlineStatus.entries())
          .filter(([_, isOnline]) => isOnline)
          .map(([id, _]) => id)
          .join(", ")
      );

      // User is still online, so mark any pending messages as delivered
      // This ensures delivery status updates even when the user is in the main screen
      try {
        // This will trigger the periodic check immediately rather than waiting
        markPendingMessagesAsDelivered(socket.userId)
          .then((count) => {
            if (count > 0) {
              console.log(
                `Marked ${count} messages as delivered when user left chat`
              );
            }
          })
          .catch((err) => {
            console.error(
              "Error marking messages as delivered on leaving chat:",
              err
            );
          });
      } catch (error) {
        console.error(
          "Error initiating delivery check on leaving chat:",
          error
        );
      }
    });

    socket.on("disconnect", () => {
      let disconnectedUserId = null;

      for (let [userId, socketId] of userSockets.entries()) {
        if (socketId === socket.id) {
          userSockets.delete(userId);
          userOnlineStatus.set(userId, false);
          disconnectedUserId = userId;
          console.log(`User ${userId} disconnected`);

          // Print current online users after disconnect
          const onlineUsers = Array.from(userOnlineStatus.entries())
            .filter(([_, isOnline]) => isOnline)
            .map(([id, _]) => id);

          console.log(
            `🔴 Remaining online users (${
              onlineUsers.length
            }): ${onlineUsers.join(", ")}`
          );
          break;
        }
      }

      if (disconnectedUserId) {
        // Clear from current chat tracking
        io.userCurrentChat.delete(disconnectedUserId);
      }
    });

    socket.on("new_message", async (data) => {
      try {
        const { senderId, receiverId, message } = data;

        if (!senderId || !receiverId || !message) {
          console.error("Invalid new_message data:", data);
          return;
        }

        // Create the message with explicit "sent" status
        const newMessage = new Message({
          sender: senderId,
          receiver: receiverId,
          text: message,
          status: "sent",
          sentAt: new Date(),
        });
        await newMessage.save();

        // Immediately acknowledge the message to the sender
        // This is critical for the sent icon to appear immediately
        socket.emit("message_acknowledged", {
          messageId: newMessage._id,
          status: "sent",
          sentAt: newMessage.sentAt,
        });

        // Populate sender and receiver usernames
        const populatedMessage = await Message.findById(newMessage._id)
          .populate("sender", "username")
          .populate("receiver", "username")
          .lean();

        const messagePayload = {
          _id: populatedMessage._id.toString(),
          text: populatedMessage.text,
          sentAt: populatedMessage.sentAt,
          sender: { username: populatedMessage.sender.username },
          receiver: { username: populatedMessage.receiver.username },
          status: "sent", // Always ensure this is set to "sent" initially
        };

        // Send message with "sent" status to sender FIRST - fixes the missing sent icon issue
        console.log(
          `First emitting new_message to sender ${senderId} with status "sent":`,
          JSON.stringify(messagePayload, null, 2)
        );
        io.to(senderId).emit("new_message", messagePayload);

        // Check if receiver is online and update message status
        // Update to delivered if user is online regardless of which chat they're viewing
        // This makes the delivered status more reliable
        if (userOnlineStatus.get(receiverId)) {
          // Update to delivered AND clear sensitive data
          // Client should have stored the encrypted data in secure storage
          await Message.findByIdAndUpdate(newMessage._id, {
            status: "delivered",
            ciphertext: null,
            nonce: null,
            headers: {
              ...message.headers,
              sanitized: true,
            },
            type: "sanitized",
          });

          console.log(
            `✅ Receiver ${receiverId} is ONLINE - marking message ${newMessage._id} as DELIVERED immediately and clearing sensitive data`
          );

          messagePayload.status = "delivered";

          // Also notify sender about delivery status change
          io.to(senderId).emit("messageStatusUpdate", {
            messageId: newMessage._id,
            status: "delivered",
          });

          console.log(
            `Notified sender ${senderId} about delivery status update to DELIVERED`
          );
        } else {
          console.log(
            `Receiver ${receiverId} is OFFLINE - message ${newMessage._id} remains as SENT`
          );
        }

        console.log(
          `Emitting new_message to receiver ${receiverId}:`,
          JSON.stringify(messagePayload, null, 2)
        );
        if (userSockets.has(receiverId)) {
          io.to(receiverId).emit("new_message", messagePayload);
          console.log(`Sent new_message to receiver ${receiverId}`);
        } else {
          console.log(
            `Receiver ${receiverId} is offline, no notification sent`
          );
        }
      } catch (error) {
        console.error("Error handling new message:", error.message);
      }
    });

    // Listen for status change acknowledgements
    socket.on("acknowledge_status", async ({ messageId }) => {
      try {
        if (!socket.userId) return;

        console.log(
          `User ${socket.userId} acknowledging status for message ${messageId}`
        );

        const message = await Message.findById(messageId);
        if (!message) {
          console.log(`Message ${messageId} not found in database`);
          return;
        }

        if (message.sender.toString() !== socket.userId) {
          console.log(
            `User ${socket.userId} is not the sender of message ${messageId}`
          );
          return;
        }

        // If message has been seen by receiver and the sender is acknowledging the status
        if (message.status === "seen") {
          console.log(
            `Deleting seen message ${messageId} after sender acknowledgment`
          );

          // Delete message immediately from database
          await Message.findByIdAndDelete(messageId);
          console.log(
            `Message ${messageId} deleted from server after sender acknowledged seen status`
          );

          // Notify both sender and receiver that the message has been deleted
          io.to(message.sender.toString()).emit("message_deleted", {
            messageId,
          });

          io.to(message.receiver.toString()).emit("message_deleted", {
            messageId,
          });
        } else {
          // For non-seen messages, just log the acknowledgment
          console.log(
            `Sender ${socket.userId} acknowledged status for message ${messageId} (status: ${message.status})`
          );
        }
      } catch (error) {
        console.error("Error acknowledging message status:", error);
      }
    });
  });

  // Helper function to mark pending messages as delivered
  async function markPendingMessagesAsDelivered(userId) {
    try {
      console.log(`Checking for undelivered messages to user ${userId}...`);

      // Find all undelivered messages sent to this user
      const pendingMessages = await Message.find({
        receiver: userId,
        status: "sent",
      });

      let deliveredCount = 0;
      for (const message of pendingMessages) {
        // Store original headers before modifying
        const originalHeaders = { ...message.headers };

        // Update status to delivered AND clear sensitive data immediately
        message.status = "delivered";

        // Clear sensitive data right after delivery
        message.ciphertext = null;
        message.nonce = null;

        // Preserve important header information but mark as sanitized
        // This is critical - we must keep dhPubKey and other cryptographic metadata
        message.headers = {
          ...originalHeaders,
          sanitized: true,
        };
        message.type = "sanitized";

        await message.save();
        deliveredCount++;

        // Notify sender about delivery
        io.to(message.sender.toString()).emit("messageStatusUpdate", {
          messageId: message._id,
          status: "delivered",
        });

        console.log(
          `Marked message ${message._id} as delivered for user ${userId} and cleared sensitive data while preserving headers`
        );
      }

      if (deliveredCount > 0) {
        console.log(
          `✅ Successfully marked ${deliveredCount} pending messages as delivered for user ${userId} and cleared sensitive data`
        );
      } else {
        console.log(`No pending messages found for user ${userId}`);
      }

      return deliveredCount;
    } catch (error) {
      console.error("Error marking pending messages as delivered:", error);
      return 0;
    }
  }

  // Set up periodic checks for undelivered messages for online users
  const checkIntervalMs = 5000; // Check every 5 seconds
  setInterval(async () => {
    try {
      // Get all online users
      const onlineUserIds = [];
      for (const [userId, isOnline] of userOnlineStatus.entries()) {
        if (isOnline) {
          onlineUserIds.push(userId);
        }
      }

      if (onlineUserIds.length === 0) {
        return; // No online users, nothing to do
      }

      console.log(`Periodic check: ${onlineUserIds.length} users online`);

      // Process each online user
      let totalDelivered = 0;
      for (const userId of onlineUserIds) {
        const delivered = await markPendingMessagesAsDelivered(userId);
        totalDelivered += delivered;
      }

      if (totalDelivered > 0) {
        console.log(
          `Periodic check delivered ${totalDelivered} messages to ${onlineUserIds.length} online users`
        );
      }
    } catch (error) {
      console.error("Error in periodic undelivered message check:", error);
    }
  }, checkIntervalMs);

  io.notifyNewMessage = async (receiverId, message) => {
    try {
      const populatedMessage = await Message.findById(message._id)
        .populate("sender", "username")
        .populate("receiver", "username")
        .lean();

      const messagePayload = {
        _id: populatedMessage._id.toString(),
        text: populatedMessage.text,
        sentAt: populatedMessage.sentAt,
        sender: { username: populatedMessage.sender.username },
        receiver: { username: populatedMessage.receiver.username },
        status: populatedMessage.status,
      };

      console.log(
        `Notifying receiver ${receiverId} of new message:`,
        JSON.stringify(messagePayload, null, 2)
      );
      if (userSockets.has(receiverId)) {
        io.to(receiverId).emit("new_message", messagePayload);
        console.log(`Sent new_message to receiver ${receiverId}`);

        // If receiver is online, mark as delivered
        if (userOnlineStatus.get(receiverId)) {
          await Message.findByIdAndUpdate(message._id, {
            status: "delivered",
            ciphertext: null,
            nonce: null,
            headers: {
              ...(populatedMessage.headers || {}),
              sanitized: true,
            },
            type: "sanitized",
          });

          console.log(
            `✅ Receiver ${receiverId} is ONLINE in notifyNewMessage - marking as DELIVERED and clearing sensitive data`
          );

          // Notify sender of delivery
          io.to(message.sender.toString()).emit("messageStatusUpdate", {
            messageId: message._id,
            status: "delivered",
          });

          console.log(
            `Notified sender ${message.sender.username} about delivery status update to DELIVERED`
          );
        } else {
          console.log(
            `Receiver ${receiverId} is offline, no notification sent`
          );
        }
      } else {
        console.log(`Receiver ${receiverId} is offline, no notification sent`);
      }
    } catch (error) {
      console.error("Error notifying new message:", error.message);
    }
  };

  // Function to check for expired messages - disabled, keeping messages forever
  async function checkForExpiredMessages() {
    // Function is now disabled - we're keeping messages forever
    console.log(
      "Message expiration check is disabled - keeping messages forever"
    );
  }

  // Disabled - no longer checking for expired messages
  // setInterval(checkForExpiredMessages, 60000);

  return io;
};

module.exports = setupSocket;
