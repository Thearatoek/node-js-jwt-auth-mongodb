const config = require("../config/auth.config");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const db = require("../models");
const User = db.user;
const Role = db.role;

const transporter = nodemailer.createTransport({
  host: 'smtp.ethereal.email',
  port: 587,
  auth: {
    user: 'derek.oreilly91@ethereal.email',
    pass: 'sx27jrhS5xzjUakn7c'
  }
});

// ─────────────────────────────────────────
// SIGNUP
// ─────────────────────────────────────────
exports.signup = async (req, res) => {
  try {
    const { username, email, password, roles } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).send({
        message: existingUser.email === email
          ? "Email already in use"
          : "Username already taken"
      });
    }

    const user = new User({
      username,
      email,
      password: bcrypt.hashSync(password, 10)
    });

    await user.save();

    if (roles && roles.length > 0) {
      const foundRoles = await Role.find({ name: { $in: roles } });
      user.roles = foundRoles.map(role => role._id);
    } else {
      const defaultRole = await Role.findOne({ name: "user" });
      user.roles = [defaultRole._id];
    }

    const savedUser = await user.save();

    res.status(201).send({
      message: "User registered successfully!",
      user: {
        id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email,
        isActive: savedUser.isActive,
        createdAt: savedUser.createdAt
      }
    });
  } catch (err) {
    if (err.name === "ValidationError") {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).send({ message: errors.join(", ") });
    }
    res.status(500).send({ message: err.message || "Error occurred while registering user" });
  }
};

// ─────────────────────────────────────────
// SIGNIN
// ─────────────────────────────────────────
exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email }).select("+password").populate("roles");

    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res.status(423).send({ message: "Account is locked. Please try again later." });
    }

    if (!user.isActive) {
      return res.status(403).send({ message: "Account is deactivated" });
    }

    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) {
      await user.incLoginAttempts();
      return res.status(401).send({ message: "Invalid password!" });
    }

    await user.resetLoginAttempts();

    const token = jwt.sign(
      { id: user._id, email: user.email },
      config.secret,
      { expiresIn: "24h" }
    );

    const authorities = user.roles.map(role => "ROLE_" + role.name.toUpperCase());

    res.status(200).send({
      id: user._id,
      username: user.username,
      email: user.email,
      roles: authorities,
      isEmailVerified: user.isEmailVerified,
      accessToken: token
    });
  } catch (err) {
    res.status(500).send({ message: err.message || "Error occurred during signin" });
  }
};

// ─────────────────────────────────────────
// FORGOT PASSWORD
// ─────────────────────────────────────────
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) return res.status(400).send({ message: "Email is required" });

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).send({ message: "If that email exists, a reset link has been sent." });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 15 * 60 * 1000;
    await user.save();

    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    console.log("EMAIL_USER:", process.env.EMAIL_USER);
    console.log("EMAIL_PASS:", process.env.EMAIL_PASS);
    await transporter.sendMail({
      from: `"Support" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Password Reset Request",
      html: `
        <h2>Password Reset</h2>
        <p>You requested a password reset. Click the link below:</p>
        <a href="${resetUrl}" style="padding:10px 20px; background:#4F46E5; color:white; border-radius:5px; text-decoration:none;">
          Reset Password
        </a>
        <p>This link expires in <strong>15 minutes</strong>.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
      `,
    });

    res.status(200).send({ message: "If that email exists, a reset link has been sent." });
  } catch (err) {
    res.status(500).send({ message: err.message || "Error occurred during forgot password" });
  }
};

// ─────────────────────────────────────────
// RESET PASSWORD
// ─────────────────────────────────────────
exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    if (!password || !confirmPassword) {
      return res.status(400).send({ message: "Both password fields are required" });
    }

    if (password !== confirmPassword) {
      return res.status(400).send({ message: "Passwords do not match" });
    }

    if (password.length < 8) {
      return res.status(400).send({ message: "Password must be at least 8 characters" });
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // 👇 MOVE DEBUG HERE - before the findOne
    console.log("Raw token:", token);
    console.log("Hashed token:", hashedToken);
    const allUsers = await User.find({}, 'resetPasswordToken resetPasswordExpires');
    console.log("All users tokens:", JSON.stringify(allUsers, null, 2));

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    console.log("User found:", user);

    if (!user) {
      return res.status(400).send({ message: "Invalid or expired reset token" });
    }

    await User.updateOne(
      { _id: user._id },
      {
        $set: { password: bcrypt.hashSync(password, 10) },
        $unset: { resetPasswordToken: "", resetPasswordExpires: "" }
      }
    );

    res.status(200).send({ message: "Password reset successfully!" });
  } catch (err) {
    res.status(500).send({
      message: err.message || "Error occurred during password reset",
    });
  }
};