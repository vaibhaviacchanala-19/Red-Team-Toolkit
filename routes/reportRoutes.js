const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const Report = require('../models/Report');
const pdfService = require('../services/pdfService');
const sessionHistory = require('../utils/sessionHistory');
const logger = require('../utils/logger');

async function historyHandler(req, res) {
  logger.info('Received /report/history request');
  try {
    if (mongoose.connection.readyState === 1) {
      const history = await Report.find()
        .select('target ip score rating severityBreakdown createdAt')
        .sort({ createdAt: -1 })
        .limit(20);

      logger.info(`MongoDB history query returned ${history.length} records`);
      if (history.length > 0) {
        logger.info('Fetched history from MongoDB');
        return res.json(history);
      }
    } else {
      logger.warn('MongoDB is not connected; using fallback history.');
    }
  } catch (error) {
    logger.warn(`History DB query failed, falling back: ${error.message}`);
  }

  try {
    const fallbackHistory = sessionHistory.getSessionHistory();
    logger.info(`Returning in-memory session history fallback with ${fallbackHistory.length} records`);
    return res.json(fallbackHistory);
  } catch (error) {
    logger.error(`Session history fallback failed: ${error.message}`);
    return res.status(500).json({ error: 'Failed to fetch history' });
  }
}

// GET /history and GET /report/history - Fetch latest 20 scans
router.get('/history', historyHandler);

// POST /report/pdf - Generate a PDF from the current browser report payload.
// This keeps PDF export working even when MongoDB is offline or a report only exists client-side.
router.post('/pdf', (req, res) => {
  try {
    const report = req.body?.report;
    if (!report || typeof report !== 'object') {
      return res.status(400).json({ error: 'Report payload is required' });
    }

    const target = String(report.target || report.fullReport?.target || 'scan').replace(/[^a-z0-9.-]/gi, '_');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=report_${target}.pdf`);
    pdfService.generateReportPDF(report, res);
  } catch (error) {
    logger.error(`PDF payload generation failed: ${error.message}`);
    if (error.stack) logger.error(error.stack);
    if (res.headersSent) return res.end();
    return res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

// GET /report/:id - Get full report
router.get('/:id', async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    if (report) return res.json(report);
  } catch (error) {
    // continue to fallback lookup
  }

  const fallback = sessionHistory.getSessionReport(req.params.id);
  if (fallback) return res.json(fallback);
  res.status(404).json({ error: 'Report not found' });
});

// GET /report/:id/pdf - Download PDF
router.get('/:id/pdf', async (req, res) => {
  try {
    let report = null;
    if (mongoose.connection.readyState === 1) {
      report = await Report.findById(req.params.id);
    }
    report = report || sessionHistory.getSessionReport(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    const normalizedReport = typeof report.toObject === 'function'
      ? report.toObject({ flattenMaps: true })
      : report;
    const fullReport = normalizedReport.fullReport || normalizedReport;

    res.setHeader('Content-Type', 'application/pdf');
    const target = String(normalizedReport.target || fullReport.target || 'scan').replace(/[^a-z0-9.-]/gi, '_');
    res.setHeader('Content-Disposition', `attachment; filename=report_${target}.pdf`);

    pdfService.generateReportPDF(normalizedReport, res);
  } catch (error) {
    logger.error(`PDF generation failed for report ${req.params.id}: ${error.message}`);
    if (error.stack) logger.error(error.stack);
    if (res.headersSent) return res.end();
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

// DELETE /report/:id - Delete report
router.delete('/:id', async (req, res) => {
  try {
    await Report.findByIdAndDelete(req.params.id);
    sessionHistory.deleteSessionReport(req.params.id);
    return res.json({ message: 'Report deleted successfully' });
  } catch (error) {
    const removed = sessionHistory.deleteSessionReport(req.params.id);
    if (removed) {
      return res.json({ message: 'Report deleted successfully' });
    }
    res.status(400).json({ error: 'Failed to delete report' });
  }
});

router.historyHandler = historyHandler;
module.exports = router;
