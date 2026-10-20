const mongoose = require('mongoose');

const securityEventSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      required: true,
      enum: ['proxy', 'rate_limit', 'waf', 'ip_block', 'auth', 'admin'],
      index: true,
    },
    outcome: {
      type: String,
      required: true,
      enum: ['allowed', 'blocked', 'warning'],
      index: true,
    },
    method: { type: String, maxlength: 12 },
    path: { type: String, maxlength: 512 },
    ip: { type: String, maxlength: 64, index: true },
    statusCode: {
      type: Number,
      min: 100,
      max: 599,
      validate: Number.isInteger,
    },
    reason: { type: String, maxlength: 240 },
    actor: { type: String, maxlength: 64 },
    requestId: { type: String, maxlength: 64 },
    durationMs: { type: Number, min: 0 },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
  },
);

securityEventSchema.index({ createdAt: -1 });
securityEventSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: Number(process.env.EVENT_RETENTION_DAYS || 30) * 86400 },
);

module.exports =
  mongoose.models.SecurityEvent ||
  mongoose.model('SecurityEvent', securityEventSchema);
