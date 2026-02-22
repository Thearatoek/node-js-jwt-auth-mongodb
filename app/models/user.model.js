const mongoose = require('mongoose');

// Define schema first
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters']
  },

  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email address'
    ]
  },

  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },

  roles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Role"
  }],

  isActive: {
    type: Boolean,
    default: true
  },

  isEmailVerified: {
    type: Boolean,
    default: false
  },

  imageUrl: {
    type: String,
    default: 'https://png.pngtree.com/png-vector/20231019/ourmid/pngtree-user-profile-avatar-png-image_10211467.png',
    validate: {
      validator: function (v) {
        return /^https?:\/\/.+\.(jpg|jpeg|png|gif|webp|svg)$/i.test(v) || v === null;
      },
      message: 'Please provide a valid image URL'
    }
  },

  lastLogin: {
    type: Date
  },

  loginAttempts: {
    type: Number,
    default: 0
  },

  lockUntil: {
    type: Date
  },

  resetPasswordToken: {
    type: String
  },

  resetPasswordExpires: {
    type: Date
  }

}, {
  timestamps: true
});

// Add indexes
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Instance methods
userSchema.methods.incLoginAttempts = function () {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours

  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
  }

  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function () {
  return this.updateOne({
    $set: { loginAttempts: 0, lastLogin: Date.now() },
    $unset: { lockUntil: 1 }
  });
};

userSchema.statics.findByCredentials = async function (email, password) {
  const user = await this.findOne({ email }).select('+password').populate('roles');

  if (!user) throw new Error('Invalid credentials');
  if (user.isLocked) throw new Error('Account is locked. Please try again later.');
  if (!user.isActive) throw new Error('Account is deactivated');

  return user;
};

// Create and export model
const User = mongoose.model("User", userSchema);
module.exports = User;