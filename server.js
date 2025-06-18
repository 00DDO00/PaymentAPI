const express = require("express");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");

const app = express();
const PORT = 3000;

const serviceAccount = require("./firebase-service-account.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://paymentapi-a3325-default-rtdb.firebaseio.com/",
});

const db = admin.database();

app.use(express.json());

class FirebaseDatabase {
  constructor() {
    this.usersRef = db.ref("users");
    this.sessionsRef = db.ref("sessions");
    this.paymentsRef = db.ref("payments");
  }

  generateId() {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
  }

  hashPassword(password) {
    return bcrypt.hashSync(password, 12);
  }

  verifyPassword(password, hash) {
    return bcrypt.compareSync(password, hash);
  }

  hashToken(token) {
    return bcrypt.hashSync(token, 5);
  }

  verifyToken(token, hash) {
    return bcrypt.compareSync(token, hash);
  }

  // Create new user
  async createUser(username, password) {
    try {
      // Check if user already exists
      const existingUser = await this.usersRef
        .orderByChild("username")
        .equalTo(username)
        .once("value");

      if (existingUser.exists()) {
        return { success: false, error: "User already exists" };
      }

      // Create new user
      const userId = this.generateId();
      const passwordHash = this.hashPassword(password);

      const userData = {
        id: userId,
        username: username,
        passwordHash: passwordHash,
        balance: 800, // cents
        failedAttempts: 0,
        lockedUntil: 0,
        createdAt: admin.database.ServerValue.TIMESTAMP,
      };

      await this.usersRef.child(userId).set(userData);

      return {
        success: true,
        user: { id: userId, username: username, balance: 8.0 },
      };
    } catch (error) {
      console.error("Create user error:", error);
      return { success: false, error: "Internal server error" };
    }
  }

  // Find user by username
  async findUserByUsername(username) {
    try {
      const snapshot = await this.usersRef
        .orderByChild("username")
        .equalTo(username)
        .once("value");

      if (snapshot.exists()) {
        const userData = Object.values(snapshot.val())[0];
        return userData;
      }
      return null;
    } catch (error) {
      console.error("Find user error:", error);
      return null;
    }
  }

  // Function for updating user failed attempts
  async updateFailedAttempts(userId, attempts, lockUntil = 0) {
    try {
      await this.usersRef.child(userId).update({
        failedAttempts: attempts,
        lockedUntil: lockUntil,
      });
      return true;
    } catch (error) {
      console.error("Update failed attempts error:", error);
      return false;
    }
  }

  // Login user
  async loginUser(username, password) {
    try {
      const user = await this.findUserByUsername(username);
      if (!user) {
        return { success: false, error: "Invalid credentials" };
      }

      // Check if account is locked
      const now = Math.floor(Date.now() / 1000);
      if (user.lockedUntil > now) {
        return { success: false, error: "Account temporarily locked" };
      }

      // Verify password
      if (!this.verifyPassword(password, user.passwordHash)) {
        // Increment failed attempts
        const newAttempts = user.failedAttempts + 1;
        const lockUntil = newAttempts >= 5 ? now + 30 * 60 : 0;

        await this.updateFailedAttempts(user.id, newAttempts, lockUntil);
        return { success: false, error: "Invalid credentials" };
      }

      // Reset failed attempts on successful login
      if (user.failedAttempts > 0) {
        await this.updateFailedAttempts(user.id, 0, 0);
      }

      // Create session
      const token = `token_${user.id}_${Date.now()}`;
      const tokenHash = this.hashToken(token);
      const expiresAt = now + 24 * 60 * 60; // 24 hours

      const sessionData = {
        id: this.generateId(),
        userId: user.id,
        tokenHash: tokenHash,
        expiresAt: expiresAt,
        createdAt: admin.database.ServerValue.TIMESTAMP,
      };

      await this.sessionsRef.child(sessionData.id).set(sessionData);

      return {
        success: true,
        token: token,
        user: {
          id: user.id,
          username: user.username,
          balance: user.balance / 100,
        },
      };
    } catch (error) {
      console.error("Login error:", error);
      return { success: false, error: "Internal server error" };
    }
  }

  // FIXED: Validate session using bcrypt.compareSync
  async validateSession(token) {
    try {
      const now = Math.floor(Date.now() / 1000);

      // Get all sessions and find the one that matches our token
      const allSessionsSnapshot = await this.sessionsRef.once("value");

      if (!allSessionsSnapshot.exists()) {
        return { success: false, error: "No active sessions" };
      }

      const allSessions = allSessionsSnapshot.val();
      let validSession = null;
      let sessionKey = null;

      // Loop through all sessions to find matching token using bcrypt.compareSync
      for (const [key, sessionData] of Object.entries(allSessions)) {
        // Token matching using bcrypt comparison
        if (this.verifyToken(token, sessionData.tokenHash)) {
          // Check if session is not expired
          if (sessionData.expiresAt > now) {
            validSession = sessionData;
            sessionKey = key;
            break;
          } else {
            // Clean up expired session
            await this.sessionsRef.child(key).remove();
          }
        }
      }

      if (!validSession) {
        return { success: false, error: "Invalid or expired token" };
      }

      // Get user data
      const userSnapshot = await this.usersRef
        .child(validSession.userId)
        .once("value");
      if (!userSnapshot.exists()) {
        return { success: false, error: "User not found" };
      }

      const userData = userSnapshot.val();
      return {
        success: true,
        user: {
          id: userData.id,
          username: userData.username,
          balance: userData.balance / 100,
        },
        sessionKey: sessionKey,
      };
    } catch (error) {
      console.error("Validate session error:", error);
      return { success: false, error: "Internal server error" };
    }
  }

  // Process payment
  async processPayment(token) {
    try {
      console.log(
        "🔍 Processing payment for token:",
        token.substring(0, 20) + "..."
      );

      // Validate session first
      const sessionValidation = await this.validateSession(token);
      if (!sessionValidation.success) {
        console.log("Session validation failed:", sessionValidation.error);
        return sessionValidation;
      }

      const userId = sessionValidation.user.id;
      const paymentAmount = 110; // cents

      console.log("Session valid for user:", userId);
      console.log("Current balance:", sessionValidation.user.balance, "USD");
      console.log("Payment amount:", paymentAmount / 100, "USD");

      // DEBUG: Check if user actually exists in Firebase
      const userCheckSnapshot = await this.usersRef.child(userId).once("value");
      if (userCheckSnapshot.exists()) {
        console.log("User data:", userCheckSnapshot.val());
      } else {
        console.log("User not found in Firebase users table");
        return {
          success: false,
          error: "User not found in database",
        };
      }

      // Check balance before transaction (convert user balance to cents)
      const userBalanceInCents = sessionValidation.user.balance * 100;
      if (userBalanceInCents < paymentAmount) {
        console.log(
          "Insufficient funds check failed:",
          userBalanceInCents,
          "cents <",
          paymentAmount,
          "cents"
        );
        return {
          success: false,
          error: "Insufficient funds",
        };
      }

      // Use Firebase transaction with retry logic
      const userRef = this.usersRef.child(userId);
      console.log("Transaction path:", userRef.toString());

      // Alternative approach: Read first, then update with transaction
      const currentUserSnapshot = await userRef.once("value");
      if (!currentUserSnapshot.exists()) {
        console.log("User not found");
        return {
          success: false,
          error: "User not found",
        };
      }

      const currentUserData = currentUserSnapshot.val();
      console.log("User data:", currentUserData);

      // Check funds before transaction
      if (currentUserData.balance < paymentAmount) {
        console.log(
          "Insufficient funds:",
          currentUserData.balance,
          "<",
          paymentAmount
        );
        return {
          success: false,
          error: "Insufficient funds",
        };
      }

      // Simple update instead of transaction for now
      const newBalance = currentUserData.balance - paymentAmount;
      console.log(
        "Updating balance from",
        currentUserData.balance,
        "to",
        newBalance
      );

      await userRef.update({
        balance: newBalance,
      });

      console.log("Balance updated successfully");

      // Record payment
      const paymentData = {
        id: this.generateId(),
        userId: userId,
        amount: paymentAmount,
        balanceBefore: currentUserData.balance,
        balanceAfter: newBalance,
        createdAt: admin.database.ServerValue.TIMESTAMP,
      };

      await this.paymentsRef.child(paymentData.id).set(paymentData);

      console.log("Payment recorded:", paymentData);

      return {
        success: true,
        payment: {
          id: paymentData.id,
          amount: paymentAmount / 100,
          balanceBefore: paymentData.balanceBefore / 100,
          balanceAfter: paymentData.balanceAfter / 100,
        },
      };
    } catch (error) {
      console.error("Payment process error:", error);
      return {
        success: false,
        error: "Payment processing failed: " + error.message,
      };
    }
  }

  // Logout
  async logout(token) {
    try {
      // Get all sessions and find the one that matches our token
      const allSessionsSnapshot = await this.sessionsRef.once("value");

      if (!allSessionsSnapshot.exists()) {
        return { success: true, message: "No active sessions to logout" };
      }

      const allSessions = allSessionsSnapshot.val();

      // Loop through all sessions to find matching token
      for (const [key, sessionData] of Object.entries(allSessions)) {
        if (this.verifyToken(token, sessionData.tokenHash)) {
          // Remove the matching session
          await this.sessionsRef.child(key).remove();
          return { success: true, message: "Logged out successfully" };
        }
      }

      return {
        success: true,
        message: "Session not found, but logout successful",
      };
    } catch (error) {
      console.error("Logout error:", error);
      return { success: false, error: "Internal server error" };
    }
  }
}

// Initialize database
const firebaseDB = new FirebaseDatabase();

//API
// Register new user
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters" });
  }

  const result = await firebaseDB.createUser(username, password);

  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  res.status(201).json({
    message: "User created successfully",
    user: result.user,
  });
});

// Login user
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const result = await firebaseDB.loginUser(username, password);

  if (!result.success) {
    return res.status(401).json({ error: result.error });
  }

  res.json({
    message: "Login successful",
    token: result.token,
    user: result.user,
  });
});

// Make payment
app.post("/payment", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  const result = await firebaseDB.processPayment(token);

  if (!result.success) {
    const statusCode = result.error === "Insufficient funds" ? 400 : 401;
    return res.status(statusCode).json({ error: result.error });
  }

  res.json({
    message: "Payment processed successfully",
    payment: result.payment,
  });
});

// Logout user
app.post("/logout", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  const result = await firebaseDB.logout(token);
  res.json({ message: result.message });
});

// Get user info
app.get("/me", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  const result = await firebaseDB.validateSession(token);

  if (!result.success) {
    return res.status(401).json({ error: result.error });
  }

  res.json({ user: result.user });
});

// Start server
app.listen(PORT, () => {
  console.log("");
  console.log("Available endpoints:");
  console.log("POST /register - Register new user");
  console.log("POST /login - User login");
  console.log("POST /payment - Make payment");
  console.log("POST /logout - User logout");
  console.log("GET /me - Get user info");
  console.log("");
});

module.exports = app;
