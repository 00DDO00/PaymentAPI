import java.util.*;
import java.io.*;
import java.security.MessageDigest;

// Simple User class
class User {
    public int id;
    public String username;
    public String passwordHash;
    public int balance; // in cents (800 = $8.00)
    public int failedAttempts;
    public long lockedUntil;
    
    public User(int id, String username, String passwordHash) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.balance = 800; // $8.00 starting balance
        this.failedAttempts = 0;
        this.lockedUntil = 0;
    }
}

// Simple Session class
class Session {
    public int id;
    public int userId;
    public String tokenHash;
    public long expiresAt;
    
    public Session(int id, int userId, String tokenHash, long expiresAt) {
        this.id = id;
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
    }
}

// Simple Payment class
class Payment {
    public int id;
    public int userId;
    public int amount; // in cents
    public int balanceBefore;
    public int balanceAfter;
    public long timestamp;
    
    public Payment(int id, int userId, int amount, int balanceBefore, int balanceAfter) {
        this.id = id;
        this.userId = userId;
        this.amount = amount;
        this.balanceBefore = balanceBefore;
        this.balanceAfter = balanceAfter;
        this.timestamp = System.currentTimeMillis() / 1000;
    }
}

// Main Database class
public class Database {
    private static List<User> users = new ArrayList<>();
    private static List<Session> sessions = new ArrayList<>();
    private static List<Payment> payments = new ArrayList<>();
    private static int nextUserId = 1;
    private static int nextSessionId = 1;
    private static int nextPaymentId = 1;
    
    // Hash password using simple approach
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return password; // fallback
        }
    }
    
    // Create new user
    public static String createUser(String username, String password) {
        // Check if user exists
        for (User user : users) {
            if (user.username.equals(username)) {
                return "ERROR: User already exists";
            }
        }
        
        // Create new user
        String passwordHash = hashPassword(password);
        User newUser = new User(nextUserId++, username, passwordHash);
        users.add(newUser);
        
        return "SUCCESS: User created with ID " + newUser.id;
    }
    
    // Login user
    public static String loginUser(String username, String password) {
        User user = null;
        
        // Find user
        for (User u : users) {
            if (u.username.equals(username)) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return "ERROR: Invalid credentials";
        }
        
        // Check if account is locked
        long now = System.currentTimeMillis() / 1000;
        if (user.lockedUntil > now) {
            return "ERROR: Account locked";
        }
        
        // Check password
        String passwordHash = hashPassword(password);
        if (!user.passwordHash.equals(passwordHash)) {
            user.failedAttempts++;
            if (user.failedAttempts >= 5) {
                user.lockedUntil = now + (30 * 60); // 30 minutes
            }
            return "ERROR: Invalid credentials";
        }
        
        // Reset failed attempts
        user.failedAttempts = 0;
        user.lockedUntil = 0;
        
        // Create session token (simple approach)
        String token = "token_" + user.id + "_" + System.currentTimeMillis();
        String tokenHash = hashPassword(token);
        long expiresAt = now + (24 * 60 * 60); // 24 hours
        
        Session session = new Session(nextSessionId++, user.id, tokenHash, expiresAt);
        sessions.add(session);
        
        return "SUCCESS: " + token + " | Balance: $" + (user.balance / 100.0);
    }
    
    // Validate session
    public static String validateSession(String token) {
        String tokenHash = hashPassword(token);
        long now = System.currentTimeMillis() / 1000;
        
        // Find valid session
        Session validSession = null;
        for (Session session : sessions) {
            if (session.tokenHash.equals(tokenHash) && session.expiresAt > now) {
                validSession = session;
                break;
            }
        }
        
        if (validSession == null) {
            return "ERROR: Invalid token";
        }
        
        // Find user
        User user = null;
        for (User u : users) {
            if (u.id == validSession.userId) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return "ERROR: User not found";
        }
        
        return "SUCCESS: " + user.username + " | Balance: $" + (user.balance / 100.0);
    }
    
    // Process payment
    public static String processPayment(String token) {
        String tokenHash = hashPassword(token);
        long now = System.currentTimeMillis() / 1000;
        
        // Find valid session
        Session validSession = null;
        for (Session session : sessions) {
            if (session.tokenHash.equals(tokenHash) && session.expiresAt > now) {
                validSession = session;
                break;
            }
        }
        
        if (validSession == null) {
            return "ERROR: Invalid token";
        }
        
        // Find user
        User user = null;
        for (User u : users) {
            if (u.id == validSession.userId) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return "ERROR: User not found";
        }
        
        // Check balance
        int paymentAmount = 110; // $1.10 in cents
        if (user.balance < paymentAmount) {
            return "ERROR: Insufficient funds";
        }
        
        // Process payment
        int balanceBefore = user.balance;
        user.balance = user.balance - paymentAmount;
        int balanceAfter = user.balance;
        
        // Record payment
        Payment payment = new Payment(nextPaymentId++, user.id, paymentAmount, balanceBefore, balanceAfter);
        payments.add(payment);
        
        return "SUCCESS: Payment processed | Amount: $1.10 | New Balance: $" + (balanceAfter / 100.0);
    }
    
    // Logout user
    public static String logout(String token) {
        String tokenHash = hashPassword(token);
        
        // Remove session
        sessions.removeIf(session -> session.tokenHash.equals(tokenHash));
        
        return "SUCCESS: Logged out";
    }
    
    // Get user info
    public static String getUserInfo(String token) {
        return validateSession(token);
    }
    
    // Main method for testing
    public static void main(String[] args) {
        System.out.println("=== Testing Database ===");
        
        // Test user creation
        System.out.println(createUser("testuser", "password123"));
        
        // Test login
        String loginResult = loginUser("testuser", "password123");
        System.out.println(loginResult);
        
        if (loginResult.startsWith("SUCCESS:")) {
            String token = loginResult.split(" ")[1];
            
            // Test payment
            System.out.println(processPayment(token));
            System.out.println(processPayment(token));
            
            // Test user info
            System.out.println(getUserInfo(token));
            
            // Test logout
            System.out.println(logout(token));
        }
    }
}