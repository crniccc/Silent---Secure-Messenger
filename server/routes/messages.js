const express = require("express");
const router = express.Router();
const {
  sendMessage,
  getMessages,
  markMessageAsRead,
  markMessageAsDelivered,
  acknowledgeMessageStatus,
  deleteMessage,
  deleteMultipleMessages,
  deleteAllUserMessages,
  deleteConversation,
} = require("../controllers/messages");
const auth = require("../middleware/auth");

router.post("/send", auth, sendMessage);
router.get("/", auth, getMessages);
router.patch("/:id/read", auth, markMessageAsRead);
router.patch("/:id/delivered", auth, markMessageAsDelivered);
router.patch("/:messageId/acknowledge", auth, acknowledgeMessageStatus);
router.delete("/:id", auth, deleteMessage);
router.post("/delete-multiple", auth, deleteMultipleMessages);
router.delete("/user/:username/all", auth, deleteAllUserMessages);
router.delete("/conversation/:user1/:user2", auth, deleteConversation);

module.exports = router;
