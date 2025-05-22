const mongoose = require("mongoose");

const inviteSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  status: {
    type: String,
    enum: ["pending", "accepted", "rejected", "removed"],
    default: "pending",
  },
  senderIdentityKey: {
    type: String,
    required: function () {
      return this.status !== "removed";
    },
  },
  senderEphemeralKey: {
    type: String,
    required: function () {
      return this.status !== "removed";
    },
  },
  usedSignedPreKeyId: {
    type: Number,
    required: function () {
      return this.status !== "removed";
    },
  },
  usedOneTimePreKeyId: { type: Number, default: null },
  encryptedPayload: {
    type: String,
    required: function () {
      return this.status !== "removed";
    },
  },
  nonce: {
    type: String,
    required: function () {
      return this.status !== "removed";
    },
  },
  confirmedBySender: { type: Boolean, default: false },
  confirmedByReceiver: { type: Boolean, default: false },
  receiverDhPubKey: { type: String, default: null }, // New field to store receiver's DH public key
  createdAt: { type: Date, default: Date.now },
});

inviteSchema.index({ sender: 1, receiver: 1, status: 1 });

module.exports = mongoose.model("Invite", inviteSchema);
