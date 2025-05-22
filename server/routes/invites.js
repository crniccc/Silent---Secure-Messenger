const express = require("express");
const router = express.Router();
const auth = require("../middleware/auth");
const {
  createInvite,
  getReceivedInvites,
  getSentInvites,
  acceptInvite,
  confirmInvite,
  rejectInvite,
  cancelInvite,
  removeContact,
  clearRemovedInvite,
  getContacts,
  deleteAllUserInvites,
} = require("../controllers/invites");

router.post("/", auth, createInvite);
router.get("/received", auth, getReceivedInvites);
router.get("/sent", auth, getSentInvites);
router.patch("/:id/accept", auth, acceptInvite);
router.patch("/:id/confirm", auth, confirmInvite);
router.patch("/:id/reject", auth, rejectInvite);
router.delete("/:id", auth, cancelInvite);
router.patch("/remove-contact", auth, removeContact);
router.delete("/:id/clear", auth, clearRemovedInvite);
router.get("/contacts", auth, getContacts);
router.delete("/user/:username/all", auth, deleteAllUserInvites);

module.exports = router;
