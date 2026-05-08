const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  target: { type: String, required: true },
  ip: { type: String, required: true },
  score: { type: Number, required: true },
  rating: { type: String, required: true },
  severityBreakdown: {
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    info: { type: Number, default: 0 }
  },
  fullReport: { type: Object, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Report', reportSchema);
