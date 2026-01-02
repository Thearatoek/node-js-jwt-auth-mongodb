const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");


// Signin controller
exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send({
        message: "Email and password are required"
      });
    }

    // Find user with password field included
    const user = await User.findOne({ email })
      .select('+password')
      .populate('roles');

    if (!user) {
      return res.status(404).send({
        message: "User not found"
      });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res.status(423).send({
        message: "Account is locked. Please try again later."
      });
    }

    // Check if account is active
    if (!user.isActive) {
      return res.status(403).send({
        message: "Account is deactivated"
      });
    }

    // Check password
    const passwordIsValid = await bcrypt.compare(password, user.password);

    if (!passwordIsValid) {
      // Increment login attempts
      await user.incLoginAttempts();

      return res.status(401).send({
        message: "Invalid password!"
      });
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Generate token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      config.secret,
      { expiresIn: '24h' }
    );

    const authorities = user.roles.map(
      role => "ROLE_" + role.name.toUpperCase()
    );

    res.status(200).send({
      id: user._id,
      username: user.username,
      email: user.email,
      roles: authorities,
      isEmailVerified: user.isEmailVerified,
      accessToken: token
    });

  } catch (err) {
    res.status(500).send({
      message: err.message || "Error occurred during signin"
    });
  }
};

// Signup controller
exports.signup = async (req, res) => {
  try {
    const { username, email, password, roles } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).send({
        message: existingUser.email === email
          ? "Email already in use"
          : "Username already taken"
      });
    }

    // Create user
    const user = new User({
      username,
      email,
      password: bcrypt.hashSync(password, 10) // Use 10 rounds instead of 8
    });

    await user.save();

    // Assign roles
    if (roles && roles.length > 0) {
      const foundRoles = await Role.find({
        name: { $in: roles }
      });

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
    // Handle validation errors
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).send({ message: errors.join(', ') });
    }

    res.status(500).send({
      message: err.message || "Error occurred while registering user"
    });
  }
};