require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const Feedback = require('./models/Feedback');

const app = express();
app.use(express.json());

// Allow connections from anywhere (We will lock this down in Phase 4)
app.use(cors({ origin: '*' }));

app.use(express.static('public'));

// --- AES-256-CBC ENCRYPTION ALGORITHM ---
const ALGORITHM = 'aes-256-cbc';
const AES_KEY = Buffer.from(process.env.AES_KEY, 'utf8');

function encryptAES(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, AES_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), encryptedData: encrypted };
}

function decryptAES(encryptedData, ivHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, AES_KEY, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- API ROUTES ---

// 1. Submit Feedback (Encrypts Email & Message)
app.post('/api/feedback', async (req, res) => {
    try {
        const { role, name, email, rating, feedbackText } = req.body;
        
        const encFeedback = encryptAES(feedbackText);
        const encEmail = encryptAES(email);

        const newFeedback = new Feedback({
            role, name, rating,
            encryptedEmail: encEmail.encryptedData,
            emailIv: encEmail.iv,
            encryptedFeedback: encFeedback.encryptedData,
            feedbackIv: encFeedback.iv
        });
        
        await newFeedback.save();
        res.status(201).json({ message: 'Feedback securely encrypted and submitted!' });
    } catch (error) {
        res.status(500).json({ error: 'Server error during submission' });
    }
});

// 2. Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
        const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// 3. Fetch & Decrypt Data for Admin Dashboard
app.get('/api/admin/feedbacks', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'No token provided' });

    try {
        jwt.verify(token, process.env.JWT_SECRET);
        const feedbacks = await Feedback.find().sort({ createdAt: -1 });
        
        const decryptedFeedbacks = feedbacks.map(item => ({
            id: item._id,
            role: item.role,
            name: item.name,
            rating: item.rating,
            date: item.createdAt,
            decryptedEmail: decryptAES(item.encryptedEmail, item.emailIv),
            decryptedMessage: decryptAES(item.encryptedFeedback, item.feedbackIv)
        }));

        res.json(decryptedFeedbacks);
    } catch (error) {
        res.status(401).json({ error: 'Decryption failed or Unauthorized' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));