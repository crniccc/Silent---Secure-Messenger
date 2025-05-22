const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  deviceId: { type: String, required: true, unique: true },
  identityKeyPublic: { type: String, required: true },
  signingKeyPublic: { type: String, required: true },
  signedPreKeyPublic: { type: String, required: true },
  signedPreKeyId: { type: Number, required: true },
  signedPreKeySignature: { type: String, required: true },
  oneTimePreKeysPublic: [
    {
      keyId: { type: Number, required: true },
      publicKey: { type: String, required: true },
    },
  ],
});

// Removing duplicate indexes as they're already created by unique: true
// userSchema.index({ username: 1 });
// userSchema.index({ deviceId: 1 });

module.exports = mongoose.model("User", userSchema);
