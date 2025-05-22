const asyncHandler = require("express-async-handler");
const Invite = require("../models/Invite");
const User = require("../models/User");

const isValidBase64 = (str) => {
  try {
    return Buffer.from(str, "base64").toString("base64") === str;
  } catch {
    return false;
  }
};

const createInvite = asyncHandler(async (req, res) => {
  const {
    receiverUsername,
    senderIdentityKey,
    senderEphemeralKey,
    usedSignedPreKeyId,
    usedOneTimePreKeyId,
    encryptedPayload,
    nonce,
  } = req.body;

  if (
    !receiverUsername ||
    !senderIdentityKey ||
    !senderEphemeralKey ||
    !usedSignedPreKeyId ||
    !encryptedPayload ||
    !nonce
  ) {
    return res
      .status(400)
      .json({ error: "All required X3DH fields must be provided" });
  }

  if (
    !isValidBase64(senderIdentityKey) ||
    !isValidBase64(senderEphemeralKey) ||
    !isValidBase64(encryptedPayload) ||
    !isValidBase64(nonce)
  ) {
    return res.status(400).json({ error: "Invalid key format" });
  }

  const sender = await User.findById(req.user.userId);
  if (!sender) {
    return res.status(404).json({ error: "Sender not found" });
  }

  const receiver = await User.findOne({ username: receiverUsername });
  if (!receiver) {
    return res.status(404).json({ error: "Receiver not found" });
  }

  if (receiver._id.toString() === req.user.userId) {
    return res.status(400).json({ error: "Cannot invite yourself" });
  }

  const existingInvite = await Invite.findOne({
    sender: req.user.userId,
    receiver: receiver._id,
    status: { $in: ["pending", "accepted"] },
  });

  if (existingInvite) {
    return res.status(400).json({ error: "Invite already sent or accepted" });
  }

  const invite = new Invite({
    sender: req.user.userId,
    receiver: receiver._id,
    status: "pending",
    senderIdentityKey,
    senderEphemeralKey,
    usedSignedPreKeyId,
    usedOneTimePreKeyId,
    encryptedPayload,
    nonce,
  });

  await invite.save();

  // Ukloni korišćeni one-time pre-key iz receiver-ovih ključeva
  if (usedOneTimePreKeyId) {
    receiver.oneTimePreKeysPublic = receiver.oneTimePreKeysPublic.filter(
      (key) => key.keyId !== usedOneTimePreKeyId
    );
    await receiver.save();
  }

  await invite.populate([
    { path: "sender", select: "username" },
    { path: "receiver", select: "username" },
  ]);

  res.status(201).json(invite);
});

const getReceivedInvites = asyncHandler(async (req, res) => {
  const invites = await Invite.find({
    receiver: req.user.userId,
    status: { $in: ["pending", "accepted", "removed"] },
  }).populate([
    { path: "sender", select: "username" },
    { path: "receiver", select: "username" },
  ]);
  res.json(invites);
});

const getSentInvites = asyncHandler(async (req, res) => {
  const invites = await Invite.find({
    sender: req.user.userId,
    status: { $in: ["pending", "accepted", "removed"] },
  }).populate([
    { path: "sender", select: "username" },
    { path: "receiver", select: "username" },
  ]);
  res.json(invites);
});

const acceptInvite = asyncHandler(async (req, res) => {
  const inviteId = req.params.id;
  const userId = req.user.userId;

  const invite = await Invite.findById(inviteId).populate("sender", "username");
  if (!invite) {
    return res.status(404).json({ error: "Invite not found" });
  }

  if (invite.receiver._id.toString() !== userId) {
    return res.status(403).json({ error: "Not authorized" });
  }

  if (invite.status !== "pending") {
    return res.status(400).json({ error: "Invite already processed" });
  }

  invite.status = "accepted";
  await invite.save();

  res.json({
    message: "Invite accepted",
    senderUsername: invite.sender.username,
    senderIdentityKey: invite.senderIdentityKey,
    senderEphemeralKey: invite.senderEphemeralKey,
    usedSignedPreKeyId: invite.usedSignedPreKeyId,
    usedOneTimePreKeyId: invite.usedOneTimePreKeyId,
    encryptedPayload: invite.encryptedPayload,
    nonce: invite.nonce,
  });
});

const confirmInvite = asyncHandler(async (req, res) => {
  const inviteId = req.params.id;
  const userId = req.user.userId;
  const { receiverDhPubKey } = req.body;

  const invite = await Invite.findById(inviteId).populate([
    { path: "sender", select: "username" },
    { path: "receiver", select: "username" },
  ]);
  if (!invite) {
    return res.status(404).json({ error: "Invite not found" });
  }

  if (invite.status !== "accepted") {
    return res.status(400).json({ error: "Invite is not in accepted state" });
  }

  if (
    invite.sender._id.toString() !== userId &&
    invite.receiver._id.toString() !== userId
  ) {
    return res.status(403).json({ error: "Not authorized" });
  }

  if (invite.sender._id.toString() === userId) {
    invite.confirmedBySender = true;
  } else if (invite.receiver._id.toString() === userId) {
    invite.confirmedByReceiver = true;
    if (receiverDhPubKey) {
      if (!isValidBase64(receiverDhPubKey)) {
        return res
          .status(400)
          .json({ error: "Invalid receiverDhPubKey format" });
      }
      const receiverDhPubKeyBytes = Buffer.from(receiverDhPubKey, "base64");
      if (receiverDhPubKeyBytes.length !== 32) {
        return res
          .status(400)
          .json({ error: "Invalid receiverDhPubKey length" });
      }
      invite.receiverDhPubKey = receiverDhPubKey;
    }
  }

  await invite.save();

  if (invite.confirmedBySender && invite.confirmedByReceiver) {
    await Invite.deleteOne({ _id: invite._id });
    return res.json({
      message: "Invite confirmed and deleted",
      receiverDhPubKey: invite.receiverDhPubKey,
    });
  }

  res.json({
    message: "Invite confirmed",
    receiverDhPubKey: invite.receiverDhPubKey,
  });
});

const getContacts = asyncHandler(async (req, res) => {
  const userId = req.user.userId;

  // Pronađi sve pozivnice gde je korisnik sender ili receiver i status je "accepted"
  const acceptedInvites = await Invite.find({
    $or: [{ sender: userId }, { receiver: userId }],
    status: "accepted",
    confirmedBySender: true,
    confirmedByReceiver: true,
  }).populate([
    { path: "sender", select: "username" },
    { path: "receiver", select: "username" },
  ]);

  // Izvuci kontakte
  const contacts = acceptedInvites.map((invite) => {
    const isSender = invite.sender._id.toString() === userId;
    return {
      username: isSender ? invite.receiver.username : invite.sender.username,
      senderIdentityKey: invite.senderIdentityKey,
      senderEphemeralKey: invite.senderEphemeralKey,
      usedSignedPreKeyId: invite.usedSignedPreKeyId,
      usedOneTimePreKeyId: invite.usedOneTimePreKeyId,
    };
  });

  res.json(contacts);
});

const rejectInvite = asyncHandler(async (req, res) => {
  const inviteId = req.params.id;
  const userId = req.user.userId;

  const invite = await Invite.findById(inviteId);
  if (!invite) {
    return res.status(404).json({ error: "Invite not found" });
  }

  if (invite.receiver._id.toString() !== userId) {
    return res.status(403).json({ error: "Not authorized" });
  }

  if (invite.status !== "pending") {
    return res.status(400).json({ error: "Invite already processed" });
  }

  await Invite.deleteOne({ _id: inviteId });

  res.json({ message: "Invite rejected" });
});

const cancelInvite = asyncHandler(async (req, res) => {
  const inviteId = req.params.id;
  const userId = req.user.userId;

  const invite = await Invite.findById(inviteId);
  if (!invite) {
    return res.status(404).json({ error: "Invite not found" });
  }

  if (invite.sender._id.toString() !== userId) {
    return res.status(403).json({ error: "Not authorized" });
  }

  if (invite.status !== "pending") {
    return res.status(400).json({ error: "Invite already processed" });
  }

  await Invite.deleteOne({ _id: inviteId });

  res.json({ message: "Invite cancelled" });
});

const removeContact = asyncHandler(async (req, res) => {
  const { contactUsername } = req.body;
  const userId = req.user.userId;

  const contact = await User.findOne({ username: contactUsername });
  if (!contact) {
    return res.status(404).json({ error: "Contact not found" });
  }

  // Obriši samo pozivnice sa statusom "accepted"
  await Invite.deleteOne({
    $or: [
      {
        sender: userId,
        receiver: contact._id,
        status: "accepted",
      },
      {
        sender: contact._id,
        receiver: userId,
        status: "accepted",
      },
    ],
  });

  // Kreiraj novu pozivnicu sa statusom "removed" samo ako ne postoji
  const existingRemovedInvite = await Invite.findOne({
    $or: [
      { sender: userId, receiver: contact._id, status: "removed" },
      { sender: contact._id, receiver: userId, status: "removed" },
    ],
  });

  if (!existingRemovedInvite) {
    const removedInvite = new Invite({
      sender: userId,
      receiver: contact._id,
      status: "removed",
    });
    await removedInvite.save();
    await removedInvite.populate([
      { path: "sender", select: "username" },
      { path: "receiver", select: "username" },
    ]);
  }

  res.json({ message: "Contact removed" });
});

const clearRemovedInvite = asyncHandler(async (req, res) => {
  const inviteId = req.params.id;
  const userId = req.user.userId;

  const invite = await Invite.findById(inviteId);
  if (!invite) {
    return res.status(404).json({ error: "Invite not found" });
  }

  if (invite.receiver._id.toString() !== userId) {
    return res.status(403).json({ error: "Not authorized" });
  }

  if (invite.status !== "removed") {
    return res.status(400).json({ error: "Invite is not in removed state" });
  }

  await Invite.deleteOne({ _id: inviteId });

  res.json({ message: "Invite cleared" });
});

const deleteAllUserInvites = asyncHandler(async (req, res) => {
  const requestingUserId = req.user?.userId;
  const { username } = req.params;

  console.log(`Request to delete all invites for user: ${username}`);

  if (!requestingUserId) {
    console.log("User ID missing in req.user:", req.user);
    res.status(401);
    throw new Error("Unauthorized: User ID missing");
  }

  // Verify the requesting user has the right to delete these invites
  // Only allow users to delete their own invites
  const user = await User.findOne({ username });

  if (!user) {
    console.log(`User not found: ${username}`);
    res.status(404);
    throw new Error("User not found");
  }

  const targetUserId = user._id.toString();

  // Security check - users can only delete their own invites
  if (targetUserId !== requestingUserId.toString()) {
    console.log(
      `Not authorized to delete invites: requesting=${requestingUserId}, target=${targetUserId}`
    );
    res.status(403);
    throw new Error("Not authorized to delete these invites");
  }

  try {
    // Find all invites where the user is either sender or receiver
    const invitesToDelete = await Invite.find({
      $or: [{ sender: targetUserId }, { receiver: targetUserId }],
    })
      .populate("sender", "username")
      .populate("receiver", "username");

    console.log(`Found ${invitesToDelete.length} invites to delete`);

    // Extract invite IDs and other user IDs for notification
    const inviteIds = [];
    const relatedUserIds = new Set();

    invitesToDelete.forEach((invite) => {
      inviteIds.push(invite._id.toString());

      // Add the other user to the related users set for notification
      if (invite.sender._id.toString() !== targetUserId) {
        relatedUserIds.add(invite.sender._id.toString());
      }
      if (invite.receiver._id.toString() !== targetUserId) {
        relatedUserIds.add(invite.receiver._id.toString());
      }
    });

    // Delete the invites
    const deleteResult = await Invite.deleteMany({
      $or: [{ sender: targetUserId }, { receiver: targetUserId }],
    });

    console.log(
      `Deleted ${deleteResult.deletedCount} invites for user ${username}`
    );

    // Notify related users about the deleted invites
    const io = req.app.get("io");

    relatedUserIds.forEach((userId) => {
      io.to(userId).emit("invitesDeleted", {
        inviteIds: inviteIds,
        byUser: username,
      });
      console.log(`Notified user ${userId} about deleted invites`);
    });

    res.status(200).json({
      message: `Successfully deleted ${deleteResult.deletedCount} invites for user ${username}`,
      deletedCount: deleteResult.deletedCount,
      inviteIds,
    });
  } catch (error) {
    console.error(`Error deleting invites for user ${username}:`, error);
    res.status(500);
    throw new Error(`Failed to delete invites: ${error.message}`);
  }
});

module.exports = {
  createInvite,
  getReceivedInvites,
  getSentInvites,
  getContacts,
  acceptInvite,
  confirmInvite,
  rejectInvite,
  cancelInvite,
  removeContact,
  clearRemovedInvite,
  deleteAllUserInvites,
};
