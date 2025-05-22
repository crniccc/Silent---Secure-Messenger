const asyncHandler = require("express-async-handler");
const User = require("../models/User");
const Message = require("../models/Message");
const Invite = require("../models/Invite");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const isValidBase64 = (str) => {
  try {
    return Buffer.from(str, "base64").toString("base64") === str;
  } catch {
    return false;
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const {
    username,
    deviceId,
    identityKeyPublic,
    signingKeyPublic,
    signedPreKeyPublic,
    signedPreKeyId,
    signedPreKeySignature,
    oneTimePreKeysPublic,
  } = req.body;

  if (
    !username ||
    !deviceId ||
    !identityKeyPublic ||
    !signingKeyPublic ||
    !signedPreKeyPublic ||
    !signedPreKeyId ||
    !signedPreKeySignature ||
    !Array.isArray(oneTimePreKeysPublic) ||
    oneTimePreKeysPublic.length === 0
  ) {
    res.status(400);
    throw new Error("All fields are required");
  }

  if (
    !isValidBase64(identityKeyPublic) ||
    !isValidBase64(signingKeyPublic) ||
    !isValidBase64(signedPreKeyPublic) ||
    !isValidBase64(signedPreKeySignature) ||
    !oneTimePreKeysPublic.every(
      (key) => key.keyId && isValidBase64(key.publicKey)
    )
  ) {
    res.status(400);
    throw new Error("Invalid key format");
  }

  const userExists = await User.findOne({ username });
  if (userExists) {
    res.status(400);
    throw new Error("Username already exists");
  }

  const user = await User.create({
    username,
    deviceId,
    identityKeyPublic,
    signingKeyPublic,
    signedPreKeyPublic,
    signedPreKeyId,
    signedPreKeySignature,
    oneTimePreKeysPublic,
  });

  if (user) {
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "30d",
    });
    res.status(201).json({
      _id: user._id,
      username: user.username,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

const loginUser = asyncHandler(async (req, res) => {
  const { username, deviceId } = req.body;

  if (!username || !deviceId) {
    res.status(400);
    throw new Error("Username and deviceId are required");
  }

  const user = await User.findOne({ username });
  if (!user) {
    res.status(401);
    throw new Error("Invalid credentials");
  }

  const token = jwt.sign(
    { userId: user._id, deviceId },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({
    _id: user._id,
    username: user.username,
    token,
  });
});

const searchUsers = asyncHandler(async (req, res) => {
  const { query } = req.query;
  if (!query) {
    res.status(400);
    throw new Error("Search query is required");
  }

  const users = await User.find({
    username: { $regex: query, $options: "i" },
    _id: { $ne: req.user.userId },
  }).select("username");

  res.json(users);
});

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find({
    _id: { $ne: req.user.userId },
  }).select("username");
  res.json(users);
});

const getUserKeys = asyncHandler(async (req, res) => {
  const { username } = req.params;
  const user = await User.findOne({ username }).select(
    "identityKeyPublic signingKeyPublic signedPreKeyPublic signedPreKeyId signedPreKeySignature oneTimePreKeysPublic"
  );

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  const oneTimePreKey =
    user.oneTimePreKeysPublic.length > 0 ? user.oneTimePreKeysPublic[0] : null;
  if (oneTimePreKey) {
    user.oneTimePreKeysPublic.pull({ _id: oneTimePreKey._id });
    await user.save();
  }

  res.json({
    identityKeyPublic: user.identityKeyPublic,
    signingKeyPublic: user.signingKeyPublic,
    signedPreKeyPublic: user.signedPreKeyPublic,
    signedPreKeyId: user.signedPreKeyId,
    signedPreKeySignature: user.signedPreKeySignature,
    oneTimePreKey: oneTimePreKey
      ? { keyId: oneTimePreKey.keyId, publicKey: oneTimePreKey.publicKey }
      : null,
  });
});

const getMyKeys = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select(
    "identityKeyPublic signingKeyPublic signedPreKeyPublic signedPreKeyId signedPreKeySignature oneTimePreKeysPublic"
  );

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  const oneTimePreKey =
    user.oneTimePreKeysPublic.length > 0 ? user.oneTimePreKeysPublic[0] : null;
  if (oneTimePreKey) {
    user.oneTimePreKeysPublic.pull({ _id: oneTimePreKey._id });
    await user.save();
  }

  res.json({
    identityKeyPublic: user.identityKeyPublic,
    signingKeyPublic: user.signingKeyPublic,
    signedPreKeyPublic: user.signedPreKeyPublic,
    signedPreKeyId: user.signedPreKeyId,
    signedPreKeySignature: user.signedPreKeySignature,
    oneTimePreKey: oneTimePreKey
      ? { keyId: oneTimePreKey.keyId, publicKey: oneTimePreKey.publicKey }
      : null,
  });
});

const deleteUser = asyncHandler(async (req, res) => {
  const { username } = req.params;

  if (username !== req.user.username) {
    res.status(403);
    throw new Error("You can only delete your own account");
  }

  await User.findByIdAndDelete(req.user.userId);
  res.status(200).json({ message: "User deleted" });
});

const deleteUserComplete = asyncHandler(async (req, res) => {
  const { username } = req.params;

  // Validate username matches the requesting user
  if (username !== req.user.username) {
    console.log(
      `Delete attempt mismatch: User ${req.user.username} trying to delete ${username}`
    );
    // Instead of throwing an error, just return a 403 with a message
    return res.status(403).json({
      error: "You can only delete your own account",
      requestedUsername: username,
      authenticatedUsername: req.user.username,
    });
  }

  // Get user ID for reference
  const userId = req.user.userId;

  try {
    // Delete all messages sent by or received by this user
    await Message.deleteMany({
      $or: [{ sender: userId }, { receiver: userId }],
    });

    // Delete all invites sent by or received by this user
    await Invite.deleteMany({
      $or: [{ sender: userId }, { receiver: userId }],
    });

    // Finally delete the user
    await User.findByIdAndDelete(userId);

    console.log(
      `User ${username} (${userId}) has been completely deleted along with all their data`
    );

    res.status(200).json({
      message: "User account and all associated data deleted successfully",
    });
  } catch (error) {
    console.error(`Error during complete deletion of user ${username}:`, error);
    res.status(500);
    throw new Error("Failed to delete user completely: " + error.message);
  }
});

module.exports = {
  registerUser,
  loginUser,
  searchUsers,
  getAllUsers,
  getUserKeys,
  getMyKeys,
  deleteUser,
  deleteUserComplete,
};
