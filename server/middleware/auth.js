const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const User = require("../models/User");

const auth = asyncHandler(async (req, res, next) => {
  // Provera Authorization header-a
  const authHeader = req.header("Authorization");
  console.log("Auth middleware: Authorization header:", authHeader);

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("Auth middleware: No token provided");
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.replace("Bearer ", "");
  console.log("Auth middleware: Token extracted:", token);

  try {
    // Verifikacija tokena
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(
      `Auth middleware: Token decoded, userId: ${decoded.userId}, deviceId: ${decoded.deviceId}`
    );

    // Pronalazak korisnika u bazi
    const user = await User.findById(decoded.userId);
    if (!user) {
      console.log("Auth middleware: User not found");
      return res.status(401).json({ error: "User not found" });
    }

    // Provera deviceId-a
    if (user.deviceId !== decoded.deviceId) {
      console.log("Auth middleware: Invalid device");
      return res.status(401).json({ error: "Invalid device" });
    }

    // Postavljanje req.user (ne req.userId)
    req.user = {
      userId: decoded.userId,
      deviceId: decoded.deviceId,
    };
    console.log("Auth middleware: req.user set:", req.user);

    next();
  } catch (error) {
    console.log(`Auth middleware: Invalid token - ${error.message}`);
    return res.status(401).json({ error: "Invalid token" });
  }
});

module.exports = auth;
