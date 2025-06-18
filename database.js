const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

// Simple JSON-based database (for development/testing)
const DB_FILE = "./payment_app_db.json";

// Initialize database
let db = {
  users: [],
  sessions: [],
  payments: [],
  lastUserId: 0,
  lastSessionId: 0,
  lastPaymentId: 0,
};

// Load existing database or create new one
function loadDatabase() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, "utf8");
      db = JSON.parse(data);
    }
  } catch (error) {
    console.log("Creating new database file");
  }
}

// Save database to file
function saveDatabase() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  } catch (error) {
    console.error("Error saving database:", error);
  }
}

// Load database on startup
loadDatabase();

// Database helper functions
const dbHelpers = {
  // Create new user
  createUser: (username, password) => {
    // Check if user already exists
    const existingUser = db.users.find((u) => u.username === username);
    if (existingUser) {
      const error = new Error("Username already exists");
      error.code = "CONSTRAINT_UNIQUE";
      throw error;
    }

    const passwordHash = bcrypt.hashSync(password, 12);
    const user = {
      id: ++db.lastUserId,
      username,
      password_hash: passwordHash,
      balance: 800, // 8.00 USD in cents
      failed_attempts: 0,
      locked_until: 0,
      created_at: Math.floor(Date.now() / 1000),
    };

    db.users.push(user);
    saveDatabase();
    return { id: user.id, username: user.username };
  },

  // Find user by username
  findUser: (username) => {
    return db.users.find((u) => u.username === username);
  },

  // Update user failed attempts
  updateFailedAttempts: (userId, attempts, lockUntil = 0) => {
    const user = db.users.find((u) => u.id === userId);
    if (user) {
      user.failed_attempts = attempts;
      user.locked_until = lockUntil;
      saveDatabase();
    }
  },

  // Save session token
  saveSession: (userId, tokenHash, expiresAt) => {
    const session = {
      id: ++db.lastSessionId,
      user_id: userId,
      token_hash: tokenHash,
      expires_at: expiresAt,
      created_at: Math.floor(Date.now() / 1000),
    };

    db.sessions.push(session);
    saveDatabase();
  },

  // Check if session is valid
  validateSession: (tokenHash) => {
    const now = Math.floor(Date.now() / 1000);
    const session = db.sessions.find(
      (s) => s.token_hash === tokenHash && s.expires_at > now
    );

    if (!session) return null;

    const user = db.users.find((u) => u.id === session.user_id);
    if (!user) return null;

    return {
      ...session,
      username: user.username,
      balance: user.balance,
    };
  },

  // Remove session (logout)
  removeSession: (tokenHash) => {
    db.sessions = db.sessions.filter((s) => s.token_hash !== tokenHash);
    saveDatabase();
  },

  // Process payment with transaction-like behavior
  processPayment: (userId) => {
    // Find user
    const userIndex = db.users.findIndex((u) => u.id === userId);
    if (userIndex === -1) {
      throw new Error("User not found");
    }

    const user = db.users[userIndex];
    const currentBalance = user.balance;
    const paymentAmount = 110; // 1.10 USD in cents

    // Check sufficient funds
    if (currentBalance < paymentAmount) {
      throw new Error("Insufficient funds");
    }

    const newBalance = currentBalance - paymentAmount;

    // Update user balance
    db.users[userIndex].balance = newBalance;

    // Record payment
    const payment = {
      id: ++db.lastPaymentId,
      user_id: userId,
      amount: paymentAmount,
      balance_before: currentBalance,
      balance_after: newBalance,
      created_at: Math.floor(Date.now() / 1000),
    };

    db.payments.push(payment);
    saveDatabase();

    return {
      paymentId: payment.id,
      amount: paymentAmount / 100, // Convert back to dollars
      balanceBefore: currentBalance / 100,
      balanceAfter: newBalance / 100,
    };
  },

  // Clean up expired sessions (optional utility)
  cleanupExpiredSessions: () => {
    const now = Math.floor(Date.now() / 1000);
    const initialCount = db.sessions.length;
    db.sessions = db.sessions.filter((s) => s.expires_at > now);

    if (db.sessions.length !== initialCount) {
      saveDatabase();
    }
  },
};

module.exports = { dbHelpers };
