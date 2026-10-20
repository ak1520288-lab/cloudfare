const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      minlength: 3,
      maxlength: 64,
      match: /^[a-z0-9][a-z0-9_.-]*$/,
    },
    passwordSalt: {
      type: String,
      required: true,
      select: false,
      match: /^[a-f\d]{32}$/i,
    },
    passwordHash: {
      type: String,
      required: true,
      select: false,
      match: /^[a-f\d]{128}$/i,
    },
    role: { type: String, enum: ['viewer'], default: 'viewer', required: true },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
