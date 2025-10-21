const express = require("express");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const userModel = require("./models/user");
const taskModel = require("./models/task");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = "1d";

// ===================================
// MIDDLEWARE SETUP
// ===================================

app.use(express.json());
app.use(cookieParser());

// Simple CORS configuration
app.use((req, res, next) => {
  // CRITICAL: Must match your frontend development port
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://task-flow-one-ebon.vercel.app"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, DELETE, OPTIONS"
  );
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
 * Middleware to verify the JWT token stored in an HTTP-only cookie.
 */
const authenticateToken = (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    // FIX APPLIED: Added return to immediately stop execution after sending 401
    return res
      .status(401)
      .json({ message: "Authentication required. No token found." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // This path was already correctly using 'return'
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
    await user.save();

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
      {
        expiresIn: JWT_EXPIRES_IN,
      }
    );

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 1, // 1 day
      sameSite: "Lax",
    });

    res.status(200).json({ message: "Login successful.", userId: user._id });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login." });
  }
});

// Route: POST /api/logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("jwt");
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
    // Find user by the ID stored in the JWT payload
    const user = await userModel
      .findById(req.user.userId)
      .select("email username createdAt");

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Respond with only safe, public profile data
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

    // Update fields if provided
    if (username) {
      // Store only the first word of the updated username
      user.username = username.trim().split(" ")[0];
    }

    if (email) {
      // Check if the new email already exists (excluding the current user's email)
      const existingUser = await userModel.findOne({ email });
      if (existingUser && existingUser._id.toString() !== user._id.toString()) {
        return res
          .status(409)
          .json({ message: "Email is already taken by another user." });
      }
      user.email = email;
    }

    await user.save();
    // Respond with updated, safe data
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

    // 1. Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "The current password you entered is incorrect." });
    }

    // 2. Hash and save the new password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // 3. Clear the cookie and force re-login for security
    res.clearCookie("jwt");

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

    // If no tasks exist, stats will be an empty array. Provide zero totals.
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
