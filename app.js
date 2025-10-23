const express = require("express");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const userModel = require("./models/user");
const taskModel = require("./models/task");
// 🛑 REMOVED: const nodemailer = require("nodemailer");
const sgMail = require("@sendgrid/mail"); // 🟢 FIX 1: Use SendGrid library

dotenv.config();

// 🟢 FIX 2: Initialize SendGrid API Key (must be set in Render environment)
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// 🛑 REMOVED: const transporter = nodemailer.createTransport({ ... });

// 🟢 FIX 3: Updated email utility function using SendGrid's API format
const sendWelcomeEmail = async (email, username) => {
  const msg = {
    to: email,
    from: process.env.TASKFLOW_EMAIL_FROM, // CRITICAL: Your verified SendGrid sender email
    subject: "Welcome to TaskFlow! Your task management journey starts now.",
    html: `<div style="font-family: sans-serif; padding: 20px; border: 1px solid #ddd;">
                <h2 style="color: #00FFC2;">Welcome to TaskFlow, ${username}!</h2>
                <p>Thank you for signing up. Your account is now active.</p>
                <p>Start organizing your tasks right away by logging into your dashboard:</p>
                <a href="https://task-flow-one-ebon.vercel.app/dashboard.html" 
                   style="background-color: #B800FF; color: white; padding: 10px 15px; 
                          text-decoration: none; border-radius: 5px; display: inline-block;">
                    Go to Your Dashboard
                </a>
                <p style="margin-top: 20px; font-size: 0.9em; color: #666;">
                    If you did not sign up for this service, please ignore this email.
                </p>
            </div>`,
  };

  try {
    await sgMail.send(msg); // 🟢 Sends via HTTPS API (Port 443)
    console.log(`Welcome email successfully sent via SendGrid to ${email}`);
  } catch (error) {
    // Log the actual SendGrid error details
    console.error(
      `SendGrid email failed to send to ${email}. ERROR:`,
      error.message
    );
  }
};

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = "1d";

// ===================================
// DATABASE CONNECTION SETUP
// ===================================
const ATLAS_URI = process.env.MONGO_URI;

if (!ATLAS_URI) {
  console.error("FATAL ERROR: MONGO_URI is not defined.");
  process.exit(1);
}

mongoose
  .connect(ATLAS_URI)
  .then(() => console.log("MongoDB Atlas connected successfully!"))
  .catch((err) => {
    console.error("MongoDB Atlas connection failed:", err.message);
  });

// ===================================
// MIDDLEWARE SETUP
// ===================================

app.use(express.json());
app.use(cookieParser());

// 🟢 FIX: Robust Dynamic CORS for Bearer Tokens
app.use((req, res, next) => {
  const allowedOrigin = "https://task-flow-one-ebon.vercel.app";
  const origin = req.headers.origin;

  if (origin && (origin === allowedOrigin || origin === `${allowedOrigin}/`)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, DELETE, OPTIONS"
  ); // CRITICAL: Must allow Authorization header for token sending
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", true);

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// ===================================
// AUTHENTICATION MIDDLEWARE
// ===================================

/**
 * 🟢 FIX: Middleware to verify the JWT token stored in the Authorization header.
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]; // Check for "Bearer <token>" format and extract the token

  const token =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;

  if (!token) {
    return res.status(401).json({
      message:
        "Authentication required. No token found in Authorization header.",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token." });
  }
};

// ===================================
// AUTHENTICATION ROUTES
// ===================================

// Route: POST /api/signup
app.post("/api/signup", async (req, res) => {
  const { email, password, username } = req.body;

  if (!email || !password || !username || password.length < 8) {
    return res.status(400).json({
      message:
        "Email, username, and a password of at least 8 characters are required.",
    });
  }

  try {
    let user = await userModel.findOne({ email });
    if (user) {
      return res
        .status(409)
        .json({ message: "That email is already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const firstName = username.trim().split(" ")[0];

    user = new userModel({
      email,
      password: hashedPassword,
      username: firstName,
    });
    await user.save(); // 🟢 Email function call remains the same, but now uses SendGrid API

    await sendWelcomeEmail(email, firstName);

    res
      .status(201)
      .json({ message: "User registered successfully. Please log in." });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Server error during registration." });
  }
});

// Route: POST /api/login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Email and password are required." });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    ); // 🟢 FIX: Return the token in the body instead of setting a cookie

    res.status(200).json({
      message: "Login successful.",
      userId: user._id,
      token: token, // 🚀 Token sent directly to frontend
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login." });
  }
});

// Route: POST /api/logout
app.post("/api/logout", (req, res) => {
  // 🟢 FIX: No cookie to clear, just success response
  res.status(200).json({ message: "Logged out successfully." });
});

// ===================================
// TASK CRUD ROUTES (PROTECTED)
// ===================================

// Apply the authentication middleware to ALL task routes below
app.use("/api/tasks", authenticateToken);

// Route: GET /api/tasks (Read All)
app.get("/api/tasks", async (req, res) => {
  try {
    const tasks = await taskModel.find({ owner: req.user.userId }).sort({
      createdAt: -1,
    });
    res.status(200).json(tasks);
  } catch (error) {
    console.error("Fetch tasks error:", error);
    res.status(500).json({ message: "Failed to retrieve tasks." });
  }
});

// Route: POST /api/tasks (Create)
app.post("/api/tasks", async (req, res) => {
  const { title, priority } = req.body;

  if (!title) {
    return res.status(400).json({ message: "Task title is required." });
  }

  try {
    const newTask = new taskModel({
      owner: req.user.userId,
      title,
      priority: priority || "Medium",
    });
    await newTask.save();
    res.status(201).json(newTask);
  } catch (error) {
    console.error("Create task error:", error);
    res.status(500).json({ message: "Failed to create task." });
  }
});

// Route: PATCH /api/tasks/:id (Update/Toggle Completion)
app.patch("/api/tasks/:id", async (req, res) => {
  const { id } = req.params;
  const updateFields = req.body;

  try {
    const task = await taskModel.findOneAndUpdate(
      { _id: id, owner: req.user.userId },
      updateFields,
      { new: true, runValidators: true }
    );

    if (!task) {
      return res
        .status(404)
        .json({ message: "Task not found or you do not have permission." });
    }

    res.status(200).json(task);
  } catch (error) {
    console.error("Update task error:", error);
    res.status(500).json({ message: "Failed to update task." });
  }
});

// Route: DELETE /api/tasks/:id (Delete)
app.delete("/api/tasks/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await taskModel.findOneAndDelete({
      _id: id,
      owner: req.user.userId,
    });

    if (!result) {
      return res
        .status(404)
        .json({ message: "Task not found or you do not have permission." });
    }

    res.status(204).send();
  } catch (error) {
    console.error("Delete task error:", error);
    res.status(500).json({ message: "Failed to delete task." });
  }
});

// Route: GET /api/profile (Read Profile Data)
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const user = await userModel
      .findById(req.user.userId)
      .select("email username createdAt");

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Fetch profile error:", error);
    res.status(500).json({ message: "Failed to retrieve profile data." });
  }
});

// Route: PATCH /api/profile (Update Profile Info)
app.patch("/api/profile", authenticateToken, async (req, res) => {
  const { username, email } = req.body;

  try {
    const user = await userModel.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: "User not found." });

    if (username) {
      user.username = username.trim().split(" ")[0];
    }

    if (email) {
      const existingUser = await userModel.findOne({ email });
      if (existingUser && existingUser._id.toString() !== user._id.toString()) {
        return res
          .status(409)
          .json({ message: "Email is already taken by another user." });
      }
      user.email = email;
    }

    await user.save();
    res.status(200).json({
      username: user.username,
      email: user.email,
      createdAt: user.createdAt,
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ message: "Failed to update profile data." });
  }
});

// Route: POST /api/profile/password (Change Password)
app.post("/api/profile/password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword || newPassword.length < 8) {
    return res.status(400).json({
      message:
        "Current password and a new password (min 8 characters) are required.",
    });
  }

  try {
    const user = await userModel.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: "User not found." });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "The current password you entered is incorrect." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save(); // 🟢 FIX: Clear cookie logic removed, no cookie to clear

    res
      .status(200)
      .json({ message: "Password changed successfully. Please log in again." });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({ message: "Failed to change password." });
  }
});

// Route: GET /api/stats (Fetch Task Aggregation for Profile Page)
app.get("/api/stats", authenticateToken, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user.userId);

    const stats = await taskModel.aggregate([
      { $match: { owner: userId } },
      {
        $group: {
          _id: null,
          totalTasks: { $sum: 1 },
          completedTotal: {
            $sum: { $cond: ["$completed", 1, 0] },
          },
          highPriority: {
            $sum: { $cond: [{ $eq: ["$priority", "High"] }, 1, 0] },
          },
        },
      },
      {
        $project: {
          _id: 0,
          totalTasks: 1,
          completedTotal: 1,
          highPriority: 1,
        },
      },
    ]);

    const result = stats[0] || {
      totalTasks: 0,
      highPriority: 0,
      completedTotal: 0,
    };

    res.status(200).json(result);
  } catch (error) {
    console.error("Fetch stats error:", error);
    res.status(500).json({ message: "Failed to retrieve task statistics." });
  }
});

// ===================================
// START SERVER
// ===================================

app.listen(PORT, () => {
  console.log(`Express server running on port ${PORT}.`);
  console.log(`Authentication Endpoints: /api/signup, /api/login, /api/logout`);
  console.log(`Task Endpoints (Protected): /api/tasks`);
  console.log(
    `Profile Endpoints (Protected): /api/profile, /api/profile/password, /api/stats`
  );
});
