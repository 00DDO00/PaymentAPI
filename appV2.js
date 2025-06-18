// Simple Payment API Server
const express = require("express");
const { spawn } = require("child_process");
const bcryptjs = require("bcryptjs");

const app = express();
const PORT = 3000;

// Middleware to parse JSON
app.use(express.json());

// Simpler approach: Use in-memory Java simulation in JavaScript
class SimpleDatabase {
  constructor() {
    this.users = [];
    this.sessions = [];
    this.payments = [];
    this.nextUserId = 1;
    this.nextSessionId = 1;
    this.nextPaymentId = 1;
  }

  // Simple hash function
  hashPassword(password) {
    return bcryptjs.hashSync(password, 12);
  }

  // Create user
  createUser(username, password) {
    // Check if user exists
    const existingUser = this.users.find((u) => u.username === username);
    if (existingUser) {
      return "ERROR: User already exists";
    }

    // Create new user
    const user = {
      id: this.nextUserId++,
      username: username,
      passwordHash: this.hashPassword(password),
      balance: 800, // $8.00 in cents
      failedAttempts: 0,
      lockedUntil: 0,
    };

    this.users.push(user);
    return `SUCCESS: User created with ID ${user.id}`;
  }

  // Login user
  loginUser(username, password) {
    const user = this.users.find((u) => u.username === username);
    if (!user) {
      return "ERROR: Invalid credentials";
    }

    // Check if account is locked
    const now = Math.floor(Date.now() / 1000);
    if (user.lockedUntil > now) {
      return "ERROR: Account locked";
    }

    // Check password
    const passwordHash = this.hashPassword(password);
    if (user.passwordHash !== passwordHash) {
      user.failedAttempts++;
      if (user.failedAttempts >= 5) {
        user.lockedUntil = now + 30 * 60; // 30 minutes
      }
      return "ERROR: Invalid credentials";
    }

    // Reset failed attempts
    user.failedAttempts = 0;
    user.lockedUntil = 0;

    // Create session token
    const token = `token_${user.id}_${Date.now()}`;
    const tokenHash = this.hashPassword(token);
    const expiresAt = now + 24 * 60 * 60; // 24 hours

    const session = {
      id: this.nextSessionId++,
      userId: user.id,
      tokenHash: tokenHash,
      expiresAt: expiresAt,
    };

    this.sessions.push(session);
    return `SUCCESS: ${token} | Balance: $${(user.balance / 100).toFixed(2)}`;
  }

  // Validate session
  validateSession(token) {
    const tokenHash = this.hashPassword(token);
    const now = Math.floor(Date.now() / 1000);

    // Find valid session
    const session = this.sessions.find(
      (s) => s.tokenHash === tokenHash && s.expiresAt > now
    );
    if (!session) {
      return "ERROR: Invalid token";
    }

    // Find user
    const user = this.users.find((u) => u.id === session.userId);
    if (!user) {
      return "ERROR: User not found";
    }

    return `SUCCESS: ${user.username} | Balance: $${(
      user.balance / 100
    ).toFixed(2)}`;
  }

  // Process payment
  processPayment(token) {
    const tokenHash = this.hashPassword(token);
    const now = Math.floor(Date.now() / 1000);

    // Find valid session
    const session = this.sessions.find(
      (s) => s.tokenHash === tokenHash && s.expiresAt > now
    );
    if (!session) {
      return "ERROR: Invalid token";
    }

    // Find user
    const user = this.users.find((u) => u.id === session.userId);
    if (!user) {
      return "ERROR: User not found";
    }

    // Check balance
    const paymentAmount = 110; // $1.10 in cents
    if (user.balance < paymentAmount) {
      return "ERROR: Insufficient funds";
    }

    // Process payment
    const balanceBefore = user.balance;
    user.balance -= paymentAmount;
    const balanceAfter = user.balance;

    // Record payment
    const payment = {
      id: this.nextPaymentId++,
      userId: user.id,
      amount: paymentAmount,
      balanceBefore: balanceBefore,
      balanceAfter: balanceAfter,
      timestamp: now,
    };

    this.payments.push(payment);
    return `SUCCESS: Payment processed | Amount: $1.10 | New Balance: $${(
      balanceAfter / 100
    ).toFixed(2)}`;
  }

  // Logout
  logout(token) {
    const tokenHash = this.hashPassword(token);
    this.sessions = this.sessions.filter((s) => s.tokenHash !== tokenHash);
    return "SUCCESS: Logged out";
  }
}

// Create database instance
const db = new SimpleDatabase();

// Routes

// Register new user
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const result = db.createUser(username, password);

  if (result.startsWith("ERROR:")) {
    return res.status(400).json({ error: result.substring(7) });
  }

  res.json({ message: result });
});

// Login user
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const result = db.loginUser(username, password);

  if (result.startsWith("ERROR:")) {
    return res.status(401).json({ error: result.substring(7) });
  }

  // Parse result to get token and balance
  const parts = result.split(" | ");
  const token = parts[0].substring(9); // Remove "SUCCESS: "
  const balance = parts[1]; // "Balance: $8.00"

  res.json({
    message: "Login successful",
    token: token,
    balance: balance,
  });
});

// Make payment
app.post("/payment", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  const result = db.processPayment(token);

  if (result.startsWith("ERROR:")) {
    return res.status(400).json({ error: result.substring(7) });
  }

  res.json({ message: result });
});

// Logout user
app.post("/logout", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  const result = db.logout(token);
  res.json({ message: result });
});

// Get user info
app.get("/me", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  const result = db.validateSession(token);

  if (result.startsWith("ERROR:")) {
    return res.status(401).json({ error: result.substring(7) });
  }

  res.json({ message: result });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log("");
  console.log("Available endpoints:");
  console.log("POST /register - Register new user");
  console.log("POST /login - User login");
  console.log("POST /payment - Make payment");
  console.log("POST /logout - User logout");
  console.log("GET /me - Get user info");
  console.log("");
  console.log("Test with:");
  console.log(
    'curl -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"test\\",\\"password\\":\\"123456\\"}"'
  );
});
