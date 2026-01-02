const db = require("../models");
const ROLES = db.ROLES;
const User = db.user;

checkDuplicateUsernameOrEmail = (req, res, next) => {
  // Check Username
  User.findOne({ username: req.body.username }).exec((err, user) => {
    if (err) {
      return res.status(500).json({
        message: "Internal server error",
        code: "SERVER_ERROR",
        description: err.message || err
      });
    }
    if (user) {
      return res.status(409).json({
        message: "Username already exists",
        code: "USERNAME_DUPLICATE",
        description: "The username you provided is already in use. Please choose another one."
      });
    }
    // Check Email
    User.findOne({ email: req.body.email }).exec((err, user) => {
      if (err) {
        return res.status(500).json({
          message: "Internal server error",
          code: "SERVER_ERROR",
          description: err.message || err
        });
      }
      if (user) {
        return res.status(409).json({
          message: "Email already exists",
          code: "EMAIL_DUPLICATE",
          description: "The email address you provided is already registered. Please use another email."
        });
      }

      next();
    });
  });
};

checkRolesExisted = (req, res, next) => {
  if (req.body.roles) {
    for (let i = 0; i < req.body.roles.length; i++) {
      if (!ROLES.includes(req.body.roles[i])) {
        res.status(400).send({
          message: `Failed! Role ${req.body.roles[i]} does not exist!`
        });
        return;
      }
    }
  }
  next();
};

const verifySignUp = {
  checkDuplicateUsernameOrEmail,
  checkRolesExisted
};

module.exports = verifySignUp;
