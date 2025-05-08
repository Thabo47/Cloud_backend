const express = require('express');
const router = express.Router();
const Query = require('../models/Query');
const { protect } = require('../middleware/auth'); // ✅ Import protect middleware

// 📨 Public route - Submit a new query
router.post('/submit', async (req, res) => {
  const { name, email, message } = req.body;

  try {
    const newQuery = new Query({ name, email, message });
    await newQuery.save();
    res.status(201).json({ message: 'Query submitted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error saving query' });
  }
});

// 🔐 Protected route - Get all queries (admin-only)
router.get('/', protect, async (req, res) => {
  try {
    const queries = await Query.find().sort({ createdAt: -1 });
    res.json(queries);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch queries' });
  }
});

module.exports = router;
