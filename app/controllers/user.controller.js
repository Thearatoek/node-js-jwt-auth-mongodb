const User = require("../models/user.model");
const Role = require("../models/role.model");

exports.allAccess = (req, res) => {
  // Assuming req.userId is set from JWT middleware
  User.findById(req.userId)
    .populate("roles", "name")
    .exec((err, user) => {
      if (err) {
        return res.status(500).json({
          message: "Internal server error",
          code: "SERVER_ERROR",
          description: err.message || err,
        });
      }

      if (!user) {
        return res.status(404).json({
          message: "User not found",
          code: "USER_NOT_FOUND",
          description: "No user found with the provided ID.",
        });
      }

      // Check if user has admin role
      const isAdmin = user.roles.some(role => role.name === "admin");

      if (isAdmin) {
        // Return all users
        User.find({})
          .populate("roles", "name")
          .exec((err, users) => {
            if (err) {
              return res.status(500).json({
                message: "Internal server error",
                code: "SERVER_ERROR",
                description: err.message || err,
              });
            }

            const userData = users.map(u => ({
              id: u._id,
              username: u.username,
              email: u.email,
              roles: u.roles.map(r => r.name),
            }));

            return res.status(200).json({
              message: "Admin: All users fetched successfully",
              data: userData,
            });
          });
      } else {
        // Not admin → public content
        return res.status(200).json({
          message: "Public Content",
        });
      }
    });
};

exports.userBoard = (req, res) => {
  // Get userId from request parameters or body
  const userId = req.params.id || req.body.id;

  if (!userId) {
    return res.status(400).json({
      message: "User ID is required",
      code: "USER_ID_REQUIRED",
      description: "Please provide a valid user ID in params or body."
    });
  }

  User.findById(userId)
    .populate("roles", "name") // populate role name only
    .exec((err, user) => {
      if (err) {
        return res.status(500).json({
          message: "Internal server error",
          code: "SERVER_ERROR",
          description: err.message || err
        });
      }

      if (!user) {
        return res.status(404).json({
          message: "User not found",
          code: "USER_NOT_FOUND",
          description: "No user found with the provided ID."
        });
      }

      return res.status(200).json({
        message: "User fetched successfully",
        data: {
          id: user._id,
          username: user.username,
          email: user.email,
          roles: user.roles.map(role => role.name)
        }
      });
    });
};

exports.adminBoard = (req, res) => {
  res.status(200).send("Admin Content.");
};

exports.moderatorBoard = (req, res) => {
  res.status(200).send("Moderator Content.");
};

