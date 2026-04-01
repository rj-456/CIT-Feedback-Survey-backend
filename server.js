require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const Feedback = require('./models/Feedback');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));
app.use(express.static('public'));

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

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// 1. Submit Feedback (Encrypts ALL fields)
app.post('/api/feedback', async (req, res) => {
    try {

        const { classification, name, email, rating, feedbackText } = req.body;     
        const encClassification = encryptAES(classification);
        const encName = encryptAES(name);
        const encRating = encryptAES(rating.toString());
        const encEmail = encryptAES(email);
        const encFeedback = encryptAES(feedbackText);

        const newFeedback = new Feedback({
            classification: encClassification.encryptedData, classificationIv: encClassification.iv,
            name: encName.encryptedData, nameIv: encName.iv,
            rating: encRating.encryptedData, ratingIv: encRating.iv,
            encryptedEmail: encEmail.encryptedData, emailIv: encEmail.iv,
            encryptedFeedback: encFeedback.encryptedData, feedbackIv: encFeedback.iv
        });
        
        await newFeedback.save();
        res.status(201).json({ message: 'Feedback fully encrypted and submitted!' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// 2. Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
        const token = jwt.sign({ classification: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// 3. Get Encrypted Dashboard Data
app.get('/api/admin/feedbacks', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'No token provided' });
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        const feedbacks = await Feedback.find().sort({ createdAt: -1 });
        res.json(feedbacks.map(f => ({
            id: f._id,
            date: f.createdAt,
            encClassification: f.classification, 
            encName: f.name,
            encRating: f.rating,
            encEmail: f.encryptedEmail,
            encMsg: f.encryptedFeedback
        })));
    } catch (error) { res.status(401).json({ error: 'Unauthorized' }); }
});

// 4. Decrypt All Fields
app.post('/api/admin/decrypt/:id', async (req, res) => {
    const token = req.headers['authorization'];
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        const f = await Feedback.findById(req.params.id);
        res.json({
            classification: decryptAES(f.classification, f.classificationIv),
            name: decryptAES(f.name, f.nameIv),
            rating: decryptAES(f.rating, f.ratingIv),
            email: decryptAES(f.encryptedEmail, f.emailIv),
            message: decryptAES(f.encryptedFeedback, f.feedbackIv)
        });
    } catch (error) { res.status(500).json({ error: 'Decryption failed' }); }
});

// 5. Delete Feedback
app.delete('/api/admin/feedback/:id', async (req, res) => {
    const token = req.headers['authorization'];
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        await Feedback.findByIdAndDelete(req.params.id);
        res.json({ message: 'Deleted' });
    } catch (error) { res.status(401).json({ error: 'Unauthorized' }); }
});

app.listen(3000, () => console.log('Running on 3000'));