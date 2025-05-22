const express = require("express");
const router = express.Router();
const asyncHandler = require("express-async-handler");
const User = require("../models/User");
const Message = require("../models/Message");
const Invite = require("../models/Invite");

// Reset endpoint for debugging/testing purposes
router.delete(
  "/reset",
  asyncHandler(async (req, res) => {
    console.log("DEBUG: Executing server-side reset");

    try {
      // Delete all messages
      const messageDeleteResult = await Message.deleteMany({});
      console.log(
        `DEBUG: Deleted ${messageDeleteResult.deletedCount} messages`
      );

      // Delete all invites
      const inviteDeleteResult = await Invite.deleteMany({});
      console.log(`DEBUG: Deleted ${inviteDeleteResult.deletedCount} invites`);

      // Delete all users
      const userDeleteResult = await User.deleteMany({});
      console.log(`DEBUG: Deleted ${userDeleteResult.deletedCount} users`);

      res.status(200).json({
        success: true,
        message: "Server reset successful",
        deleted: {
          messages: messageDeleteResult.deletedCount,
          invites: inviteDeleteResult.deletedCount,
          users: userDeleteResult.deletedCount,
        },
      });
    } catch (error) {
      console.error("DEBUG: Reset error:", error);
      res.status(500).json({
        success: false,
        error: "Server reset failed: " + error.message,
      });
    }
  })
);

// Endpoint specifically for safe password reset - no auth required
router.delete(
  "/safe-reset/:username",
  asyncHandler(async (req, res) => {
    const { username } = req.params;
    console.log(`DEBUG: Executing safe password reset for user: ${username}`);

    try {
      // Find the user first to get their ID
      const user = await User.findOne({ username });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: `User ${username} not found`,
        });
      }

      const userId = user._id;

      // Delete all messages for this user
      const messageDeleteResult = await Message.deleteMany({
        $or: [{ sender: userId }, { receiver: userId }],
      });
      console.log(
        `DEBUG: Deleted ${messageDeleteResult.deletedCount} messages for ${username}`
      );

      // Delete all invites for this user
      const inviteDeleteResult = await Invite.deleteMany({
        $or: [{ sender: userId }, { receiver: userId }],
      });
      console.log(
        `DEBUG: Deleted ${inviteDeleteResult.deletedCount} invites for ${username}`
      );

      // Delete the user
      await User.findByIdAndDelete(userId);
      console.log(`DEBUG: Deleted user ${username}`);

      res.status(200).json({
        success: true,
        message: `Safe reset successful for user ${username}`,
        deleted: {
          user: username,
          messages: messageDeleteResult.deletedCount,
          invites: inviteDeleteResult.deletedCount,
        },
      });
    } catch (error) {
      console.error(`DEBUG: Safe reset error for user ${username}:`, error);
      res.status(500).json({
        success: false,
        error: `Safe reset failed for user ${username}: ${error.message}`,
      });
    }
  })
);

module.exports = router;
