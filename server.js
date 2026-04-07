require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const Feedback = require('./models/Feedback');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ─── MongoDB Connection ───────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ MongoDB Error:', err));

// ─── ElGamal Key Setup ────────────────────────────────────────────────────────
const p = BigInt(process.env.ELGAMAL_P);
const g = BigInt(process.env.ELGAMAL_G);
const x = BigInt(process.env.ELGAMAL_X);
const y = BigInt(process.env.ELGAMAL_Y);

// ─── ElGamal Core Engine ──────────────────────────────────────────────────────
function power(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) result = (result * base) % mod;
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return result;
}

function encryptElGamal(text) {
    const msgHex = Buffer.from(text, 'utf8').toString('hex');
    const m = BigInt('0x' + msgHex);
    if (m >= p) throw new Error(`Message too large for prime P. Input: "${text}"`);
    const k = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % (p - 2n) + 1n;
    const c1 = power(g, k, p);
    const s  = power(y, k, p);
    const c2 = (m * s) % p;
    return { c1: c1.toString(), c2: c2.toString() };
}

function decryptElGamal(c1Str, c2Str) {
    const c1 = BigInt(c1Str);
    const c2 = BigInt(c2Str);
    const s    = power(c1, x, p);
    const sInv = power(s, p - 2n, p);
    const m    = (c2 * sInv) % p;
    let hex = m.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return Buffer.from(hex, 'hex').toString('utf8');
}

// ─── Simple Token Store ───────────────────────────────────────────────────────
let activeToken = null;

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    const token = req.headers['authorization'];
    if (!token || token !== activeToken) {
        return res.status(401).json({ error: 'Unauthorized.' });
    }
    next();
}

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// ─── Admin Login ──────────────────────────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (
        username === process.env.ADMIN_USERNAME &&
        password === process.env.ADMIN_PASSWORD
    ) {
        activeToken = crypto.randomBytes(32).toString('hex');
        res.status(200).json({ token: activeToken });
    } else {
        res.status(401).json({ error: 'Invalid credentials.' });
    }
});

// ─── Get All Feedbacks (Encrypted) ───────────────────────────────────────────
app.get('/api/admin/feedbacks', requireAuth, async (req, res) => {
    try {
        const records = await Feedback.find().sort({ createdAt: -1 });
        const list = records.map(f => ({
            id:                f._id,
            date:              f.createdAt,
            encName:           `c1:${f.name.c1.slice(0, 12)}...`,
            encClassification: `c1:${f.classification.c1.slice(0, 12)}...`,
            encEmail:          `c1:${f.encryptedEmail.c1.slice(0, 12)}...`,
            encRating:         `c1:${f.rating.c1.slice(0, 12)}...`,
            encMsg:            `c1:${f.encryptedFeedback.c1.slice(0, 12)}...`,
        }));
        res.status(200).json(list);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch records.', detail: err.message });
    }
});

// ─── Decrypt Single Record ────────────────────────────────────────────────────
app.post('/api/admin/decrypt/:id', requireAuth, async (req, res) => {
    try {
        const record = await Feedback.findById(req.params.id);
        if (!record) return res.status(404).json({ error: 'Record not found.' });
        res.status(200).json({
            name:           decryptElGamal(record.name.c1,              record.name.c2),
            classification: decryptElGamal(record.classification.c1,    record.classification.c2),
            email:          decryptElGamal(record.encryptedEmail.c1,    record.encryptedEmail.c2),
            rating:         decryptElGamal(record.rating.c1,            record.rating.c2),
            message:        decryptElGamal(record.encryptedFeedback.c1, record.encryptedFeedback.c2),
        });
    } catch (err) {
        res.status(500).json({ error: 'Decryption failed.', detail: err.message });
    }
});

// ─── Delete Single Record ─────────────────────────────────────────────────────
app.delete('/api/admin/feedback/:id', requireAuth, async (req, res) => {
    try {
        await Feedback.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: 'Record deleted.' });
    } catch (err) {
        res.status(500).json({ error: 'Delete failed.', detail: err.message });
    }
});

// ─── Submit Feedback ──────────────────────────────────────────────────────────
app.post('/api/feedback', async (req, res) => {
    try {
        const { classification, name, email, rating, feedbackText } = req.body;
        if (!classification || !rating || !feedbackText) {
            return res.status(400).json({ error: 'Missing required fields.' });
        }
        const encryptedData = new Feedback({
            classification:    encryptElGamal(classification),
            name:              encryptElGamal(name  || 'Anonymous'),
            rating:            encryptElGamal(String(rating)),
            encryptedEmail:    encryptElGamal(email || 'Not provided'),
            encryptedFeedback: encryptElGamal(feedbackText),
        });
        await encryptedData.save();
        console.log(`✅ Feedback vaulted [${new Date().toISOString()}]`);
        res.status(201).json({ message: '✅ Feedback encrypted and stored successfully.' });
    } catch (err) {
        console.error('❌ Encryption/Save Error:', err.message);
        res.status(500).json({ error: 'Server error during encryption.', detail: err.message });
    }
});

// ─── Server Start ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));