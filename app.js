const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { dbHelpers } = require("./database");

const app = express();
const PORT = 3000;
const JWT_SECRET = "your-super-secret-key-change-in-production";

// Middleware
app.use(express.json());

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: { error: "Too many login attempts, try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});

// Helper function to hash tokens
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const tokenHash = hashToken(token);

    const session = dbHelpers.validateSession(tokenHash);
    if (!session) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }

    req.user = {
      id: session.user_id,
      username: session.username,
      balance: session.balance / 100, // Convert cents to dollars
    };
    next();
  } catch (error) {
    res.status(403).json({ error: "Invalid token" });
  }
}

// Routes

// POST /auth/login - User login
app.post("/auth/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const user = dbHelpers.findUser(username);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check if account is locked
    const now = Math.floor(Date.now() / 1000);
    if (user.locked_until > now) {
      return res.status(423).json({
        error: "Account temporarily locked due to failed login attempts",
      });
    }

    // Verify password
    const validPassword = bcrypt.compareSync(password, user.password_hash);
    if (!validPassword) {
      // Increment failed attempts
      const newAttempts = user.failed_attempts + 1;
      const lockUntil = newAttempts >= 5 ? now + 30 * 60 : 0; // Lock for 30 minutes after 5 failed attempts

      dbHelpers.updateFailedAttempts(user.id, newAttempts, lockUntil);

      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Reset failed attempts on successful login
    if (user.failed_attempts > 0) {
      dbHelpers.updateFailedAttempts(user.id, 0, 0);
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Save session in database
    const tokenHash = hashToken(token);
    const expiresAt = now + 24 * 60 * 60; // 24 hours
    dbHelpers.saveSession(user.id, tokenHash, expiresAt);

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        balance: user.balance / 100, // Convert cents to dollars
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /auth/logout - User logout
app.post("/auth/logout", authenticateToken, (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader.split(" ")[1];
    const tokenHash = hashToken(token);

    dbHelpers.removeSession(tokenHash);
    res.json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /payments - Process payment
app.post("/payments", authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;

    const payment = dbHelpers.processPayment(userId);

    res.json({
      message: "Payment processed successfully",
      payment: {
        id: payment.paymentId,
        amount: payment.amount,
        balanceBefore: payment.balanceBefore,
        balanceAfter: payment.balanceAfter,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("Payment error:", error);

    if (error.message === "Insufficient funds") {
      return res.status(400).json({ error: "Insufficient funds" });
    }

    res.status(500).json({ error: "Payment processing failed" });
  }
});

// POST /auth/register - Register new user (helper endpoint for testing)
app.post("/auth/register", (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }

    const user = dbHelpers.createUser(username, password);
    res.status(201).json({
      message: "User created successfully",
      user: { id: user.id, username: user.username, balance: 8.0 },
    });
  } catch (error) {
    if (error.code === "CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Username already exists" });
    }

    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /me - Get current user info (helper endpoint)
app.get("/me", authenticateToken, (req, res) => {
  res.json({
    user: req.user,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log("Available endpoints:");
  console.log("POST /auth/register - Register new user");
  console.log("POST /auth/login - User login");
  console.log("POST /auth/logout - User logout");
  console.log("POST /payments - Process payment");
  console.log("GET /me - Get current user info");
});

module.exports = app;
