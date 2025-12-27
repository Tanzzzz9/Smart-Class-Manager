const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const captchaSystem = require('./captcha-utils');
const router = express.Router();

// Database connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'smart_curriculum',
    password: 'your_password',
    port: 5432,
});

// Generate CAPTCHA endpoint
router.get('/captcha/generate', (req, res) => {
    try {
        const captcha = captchaSystem.generateCaptcha();
        res.json({
            success: true,
            captchaId: captcha.id,
            captchaText: captcha.text
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to generate CAPTCHA'
        });
    }
});

// Admin login with CAPTCHA verification
router.post('/login', async (req, res) => {
    const { username, password, captchaId, captchaInput } = req.body;
    const ipAddress = req.ip;
    
    try {
        // Verify CAPTCHA first
        const captchaValidation = captchaSystem.validateCaptcha(captchaId, captchaInput);
        if (!captchaValidation.valid) {
            await pool.query(
                'INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES ($1, $2, $3, $4)',
                [username, ipAddress, false, `CAPTCHA failed: ${captchaValidation.reason}`]
            );
            
            return res.status(400).json({ 
                success: false, 
                message: captchaValidation.reason,
                attemptsRemaining: captchaValidation.attemptsRemaining
            });
        }

        // Rest of your existing login logic...
        // Check if user exists and is admin
        const userResult = await pool.query(
            'SELECT id, username, password_hash, full_name, email, is_active FROM users WHERE username = $1 AND user_type = $2',
            [username, 'admin']
        );

        if (userResult.rows.length === 0) {
            await pool.query(
                'INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES ($1, $2, $3, $4)',
                [username, ipAddress, false, 'User not found']
            );
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        const user = userResult.rows[0];

        // Check if user is active
        if (!user.is_active) {
            await pool.query(
                'INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES ($1, $2, $3, $4)',
                [username, ipAddress, false, 'Account inactive']
            );
            return res.status(401).json({ 
                success: false, 
                message: 'Account is deactivated' 
            });
        }

        // Verify password
        const passwordValid = await bcrypt.compare(password, user.password_hash);
        if (!passwordValid) {
            await pool.query(
                'INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES ($1, $2, $3, $4)',
                [username, ipAddress, false, 'Invalid password']
            );
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.id, 
                username: user.username,
                userType: 'admin'
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );

        // Create session record
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await pool.query(
            'INSERT INTO admin_sessions (admin_id, session_token, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5)',
            [user.id, token, ipAddress, req.get('User-Agent'), expiresAt]
        );

        // Record successful login
        await pool.query(
            'INSERT INTO login_attempts (username, ip_address, success) VALUES ($1, $2, $3)',
            [username, ipAddress, true]
        );

        // Return success response
        res.json({
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                id: user.id,
                username: user.username,
                fullName: user.full_name,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

module.exports = router;