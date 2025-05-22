const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  ciphertext: {
    type: String,
    // No longer required - can be set to null or empty after delivery
  },
  nonce: {
    type: String,
    // No longer required - can be set to null or empty after delivery
  },
  headers: {
    dhPubKey: { type: String },
    prevChainLength: { type: Number, default: 0 },
    messageIndex: { type: Number, default: 0 },
    sanitized: { type: Boolean, default: false },
  },
  type: {
    type: String,
    enum: ["text", "image", "sanitized"],
    default: "text",
  },
  sentAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  status: {
    type: String,
    enum: ["sent", "delivered", "seen", "expired"],
    default: "sent",
  },
});

messageSchema.index({ receiver: 1, sentAt: 1 });
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("Message", messageSchema);
