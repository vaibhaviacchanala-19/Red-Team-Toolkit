const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const mongoose = require('mongoose');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const scanRoutes = require('./routes/scanRoutes');
const reportRoutes = require('./routes/reportRoutes');
const logger = require('./utils/logger');

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/redteamtoolkit';

mongoose.set('bufferCommands', false);
mongoose.connect(MONGO_URI, {
  serverSelectionTimeoutMS: Number(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS || 3000)
}).then(() => {
  logger.success('Connected to MongoDB');
}).catch(err => {
  logger.error(`MongoDB connection error: ${err.message}`);
  if (err.message.includes('authentication failed')) {
    logger.warn('Check your MONGODB_URI credentials in .env');
  } else if (err.message.includes('ECONNREFUSED')) {
    logger.warn('MongoDB connection refused. Is the service running?');
  }
});

const app = express();
const PORT = process.env.PORT || 3001;

app.set('trust proxy', 1);

logger.info('--- Red Team Toolkit Startup ---');
logger.info(`NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
logger.info(`PORT: ${PORT}`);
logger.info(`VT Key Loaded: ${Boolean(process.env.VT_API_KEY)}`);
logger.info(`AbuseIPDB Key Loaded: ${Boolean(process.env.ABUSEIPDB_API_KEY)}`);
logger.info('--------------------------------');

app.use(morgan('combined'));
app.use(compression());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

function sanitizeString(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') return;

  Object.keys(obj).forEach((key) => {
    const value = obj[key];

    if (/^\$|\./.test(key)) {
      delete obj[key];
      const safeKey = key.replace(/^\$|\./g, '');
      if (
        safeKey &&
        safeKey !== '__proto__' &&
        safeKey !== 'constructor' &&
        safeKey !== 'prototype'
      ) {
        obj[safeKey] = value;
      }
    } else if (typeof value === 'string') {
      obj[key] = sanitizeString(value);
    } else if (typeof value === 'object' && value !== null) {
      sanitizeObject(value);
    }
  });
}

function sanitizeRequest(req, res, next) {
  ['body', 'params'].forEach((key) => sanitizeObject(req[key]));

  if (req.query && typeof req.query === 'object') {
    sanitizeObject(req.query);
  }

  next();
}

app.use(sanitizeRequest);
app.use(express.static('public'));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down and try again later.' }
});
app.use('/scan', limiter);

app.use('/scan', scanRoutes);
app.use('/report', reportRoutes);
app.get('/history', reportRoutes.historyHandler);

app.get('/health', (req, res) => {
  res.json({ status: 'Red Team Toolkit is active', version: '1.0.0' });
});

app.use((err, req, res, next) => {
  logger.error(`[Global Error]: ${err.message}`);
  if (err.stack) {
    logger.error(err.stack);
  }
  const status = err.status || err.statusCode || 500;
  const isClientError = status >= 400 && status < 500;
  res.status(status).json({
    error: isClientError || process.env.NODE_ENV !== 'production'
      ? err.message
      : 'Internal Server Error'
  });
});

process.on('unhandledRejection', (reason) => {
  logger.error(`Unhandled Rejection: ${reason}`);
});

process.on('uncaughtException', (err) => {
  logger.error(`Uncaught Exception: ${err.message}`);
  if (/mongo|mongoose|server selection|ECONNREFUSED/i.test(err.message)) {
    logger.warn('Continuing without MongoDB persistence. Reports remain available for the current browser session.');
    return;
  }
  process.exit(1);
});

const server = app.listen(PORT, () => {
  logger.success(`Red Team Toolkit server listening on port ${PORT}`);
  logger.info(`Open http://localhost:${PORT}`);
});

server.on('error', (error) => {
  logger.error(`HTTP server error: ${error.message}`);
});

server.on('close', () => {
  logger.warn('HTTP server closed.');
});

process.on('SIGTERM', () => {
  logger.warn('Received SIGTERM; shutting down HTTP server.');
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  logger.warn('Received SIGINT; shutting down HTTP server.');
  server.close(() => process.exit(0));
});
