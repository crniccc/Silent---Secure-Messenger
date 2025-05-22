const express = require("express");
const router = express.Router();
const {
  registerUser,
  loginUser,
  searchUsers,
  getAllUsers,
  getUserKeys,
  getMyKeys,
  deleteUser,
  deleteUserComplete,
} = require("../controllers/users");
const auth = require("../middleware/auth");

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/search", auth, searchUsers);
router.get("/", auth, getAllUsers);
router.get("/keys/:username", auth, getUserKeys);
router.get("/my-keys", auth, getMyKeys);
router.delete("/:username", auth, deleteUser);
router.delete("/:username/complete", auth, deleteUserComplete);

module.exports = router;
