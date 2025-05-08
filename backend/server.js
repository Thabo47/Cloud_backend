const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const colors = require('colors');

// Load environment variables
dotenv.config({ path: './.env' });

// Build MongoDB connection string securely
const MONGO_URI = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@thabo4231.6aat015.mongodb.net/${process.env.MONGO_DB_NAME}?retryWrites=true&w=majority&appName=Thabo4231`;

// Initialize Express app
const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  exposedHeaders: ['Content-Length', 'X-Foo', 'X-Bar']
}));

app.use(express.json());

// Database connection
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected'.cyan.underline.bold))
  .catch(err => console.error(`MongoDB Connection Error: ${err.message}`.red));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/queries', require('./routes/queries'));
app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Server Error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`\nServer running in ${process.env.NODE_ENV} mode on port ${PORT}`.yellow.bold);
  console.log(`➜ Local: http://localhost:${PORT}/`.white);
});

// Graceful Shutdown
process.on('unhandledRejection', (err) => {
  console.log(`Unhandled Rejection: ${err.message}`.red.bold);
  server.close(() => process.exit(1));
});

process.on('SIGTERM', () => {
  console.log('SIGTERM RECEIVED. Shutting down gracefully...'.yellow);
  server.close(() => {
    console.log('Process terminated'.red);
    process.exit(0);
  });
});
