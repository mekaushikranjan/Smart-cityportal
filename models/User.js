const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "user" },

  // OTP verification fields
  emailVerified: { type: Boolean, default: false },
  otp: String, // Now stores hashed OTP
  otpExpires: Date,
  otpAttempts: { type: Number, default: 0 } // Track OTP attempts
});

const User = mongoose.model("User", userSchema);

module.exports = User;
