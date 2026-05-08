const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const logger = require('../utils/logger');
const sessionHistory = require('../utils/sessionHistory');
const Report = require('../models/Report');
const scanService = require('../services/scanService');

router.post('/', async (req, res, next) => {
  const target = (req.body.target || '').trim();

  if (!target) {
    return res.status(400).json({ error: 'Invalid target domain or IP address.' });
  }

  try {
    logger.info(`Starting scan for ${target}`);

    const fullReport = await scanService.runAssessment(target);

    const sessionReport = {
      _id: new mongoose.Types.ObjectId().toString(),
      target: fullReport.target,
      ip: fullReport.ip,
      score: fullReport.score,
      rating: fullReport.rating,
      fullReport,
      createdAt: new Date()
    };

    if (mongoose.connection.readyState === 1 && mongoose.connection.db) {
      const savedReport = new Report({
        target: fullReport.target,
        ip: fullReport.ip,
        score: fullReport.score,
        rating: fullReport.rating,
        severityBreakdown: fullReport.breakdown,
        fullReport
      });
      await savedReport.save();
      sessionReport._id = savedReport._id.toString();
    }

    sessionHistory.addSessionReport(sessionReport);
    logger.success(`Scan complete: ${fullReport.target} - Score ${fullReport.score}`);
    res.json({ _id: sessionReport._id, ...fullReport });
  } catch (error) {
    logger.error(`Scan failed: ${error.message}`);
    next(error);
  }
});

module.exports = router;
