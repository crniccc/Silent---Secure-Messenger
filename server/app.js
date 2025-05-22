const express = require("express");
const http = require("http");
const connectDB = require("./config/db");
const userRoutes = require("./routes/users");
const inviteRoutes = require("./routes/invites");
const messageRoutes = require("./routes/messages");
const debugRoutes = require("./routes/debug");
const setupSocket = require("./socket");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
require("dotenv").config();

const app = express();

// Create HTTP server (no SSL)
const server = http.createServer(app);

// Socket.io
const io = setupSocket(server);
app.set("io", io);

// Middleware
app.use(helmet());
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minuta
    max: 100, // Max 100 zahtjeva
  })
);

// Log incoming requests
app.use((req, res, next) => {
  console.log(`Incoming request: ${req.method} ${req.url}`);
  next();
});

// Testna ruta za Socket.io
app.get("/test-socket", (req, res) => {
  res.sendFile(__dirname + "/test-socket.html");
});

// Rute
app.use("/api/users", userRoutes);
console.log("User routes mounted at /api/users");

app.use("/api/invites", inviteRoutes);
console.log("Invite routes mounted at /api/invites");

app.use("/api/messages", messageRoutes);
console.log("Message routes mounted at /api/messages");

// Debug routes - always mount for now
app.use("/api/debug", debugRoutes);
console.log("Debug routes mounted at /api/debug");

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Error middleware caught:", err.message);
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode).json({
    error: err.message || "Server Error",
    stack: process.env.NODE_ENV === "production" ? null : err.stack,
  });
});

// Pokretanje
connectDB()
  .then(() => {
    server.listen(process.env.PORT || 3000, () => {
      console.log(`HTTP Server running on port ${process.env.PORT || 3000}`);
    });
  })
  .catch((error) => {
    console.error("Failed to connect to database:", error.message);
    process.exit(1);
  });
