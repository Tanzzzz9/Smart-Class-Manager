// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'smart-curriculum-secret-key';

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running!', timestamp: new Date().toISOString() });
});

// Teacher Login API
app.post('/api/teacher-login', async (req, res) => {
  try {
    console.log('Login request received:', req.body);
    
    const { full_name, password, captcha } = req.body;

    // Basic validation
    if (!full_name || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Full name and password are required' 
      });
    }

    if (!captcha) {
      return res.status(400).json({ 
        success: false, 
        error: 'CAPTCHA is required' 
      });
    }

    // Look up teacher by full_name
    const teacherQuery = `
      SELECT u.* 
      FROM users u 
      WHERE u.full_name = $1 
        AND u.user_type = 'teacher' 
        AND u.is_active = true
    `;

    const result = await pool.query(teacherQuery, [full_name]);
    console.log('Database query result:', result.rows);

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid full name or password' 
      });
    }

    const teacher = result.rows[0];
    console.log('Teacher found:', teacher.full_name);

    // For testing: If password is 'teacher123', allow login without bcrypt check
    let validPassword = false;
    
    if (password === 'teacher123') {
      // For testing purposes only - check plain text password
      validPassword = true;
      console.log('Password validation: TEST MODE - Using plain text comparison');
    } else {
      // Normal bcrypt comparison (use this in production)
      validPassword = await bcrypt.compare(password, teacher.password_hash);
      console.log('Password validation: Production mode - Using bcrypt');
    }

    if (!validPassword) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid full name or password' 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: teacher.id, 
        userType: teacher.user_type,
        fullName: teacher.full_name
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('Login successful for:', teacher.full_name);

    res.json({
      success: true,
      token,
      user: {
        id: teacher.id,
        username: teacher.username,
        fullName: teacher.full_name,
        email: teacher.email,
        phone: teacher.phone
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
});