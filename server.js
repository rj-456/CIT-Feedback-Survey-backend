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
/**
 * ELGAMAL ASYMMETRIC CRYPTOGRAPHY PARAMETERS
 * In asymmetric encryption, there is a public key (for encrypting) 
 * and a private key (for decrypting).
 * * p: The Safe Prime. A massive number that defines the mathematical "field".
 * g: The Generator. Used as the base for exponentiation.
 * x: The PRIVATE KEY. Only known to the server. Kept secret to decrypt data.
 * y: The PUBLIC KEY. Derived from (g^x mod p). Used to encrypt data.
 */
const p = BigInt(process.env.ELGAMAL_P);
const g = BigInt(process.env.ELGAMAL_G);
const x = BigInt(process.env.ELGAMAL_X);
const y = BigInt(process.env.ELGAMAL_Y);

// ─── ElGamal Core Engine ──────────────────────────────────────────────────────

/**
 * MODULAR EXPONENTIATION (base^exp % mod)
 * This is the heart of ElGamal. It calculates extremely large powers 
 * without causing memory overflow (which Math.pow would do).
 * It uses the "Square-and-Multiply" algorithm for efficiency.
 */
function power(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        // If the current bit of the exponent is 1, multiply the result
        if (exp % 2n === 1n) result = (result * base) % mod;
        // Square the base for the next iteration
        base = (base * base) % mod;
        // Shift to the next bit
        exp = exp / 2n;
    }
    return result;
}

/**
 * ELGAMAL ENCRYPTION FUNCTION
 * Converts plaintext text into a pair of ciphertexts (c1, c2).
 */
function encryptElGamal(text) {
    // 1. Encoding: Convert the text string into a numerical format (Hex to BigInt)
    // ElGamal math only works on numbers, not text characters.
    const msgHex = Buffer.from(text, 'utf8').toString('hex');
    const m = BigInt('0x' + msgHex);

    // Safety Check: The numerical message (m) MUST be smaller than the prime (p)
    if (m >= p) throw new Error(`Message too large for prime P. Input: "${text}"`);
    
    // 2. Ephemeral Key (k): Generate a random, one-time-use key for this specific message.
    // This ensures that encrypting the same text twice yields completely different ciphertexts.
    const k = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % (p - 2n) + 1n;

    // 3. Calculate c1: The "clue" needed by the receiver to reconstruct the shared secret.
    // c1 = g^k mod p
    const c1 = power(g, k, p);

    // 4. Calculate Shared Secret (s): Combine the public key (y) with the ephemeral key (k).
    // s = y^k mod p
    const s  = power(y, k, p);

    // 5. Calculate c2: Mask the actual message (m) using the shared secret (s).
    // c2 = (m * s) mod p
    const c2 = (m * s) % p;

    // Return the ciphertext pair as strings for safe database storage
    return { c1: c1.toString(), c2: c2.toString() };
}

/**
 * ELGAMAL DECRYPTION FUNCTION
 * Reconstructs the original text using the private key (x) and the ciphertext pair (c1, c2).
 */
function decryptElGamal(c1Str, c2Str) {
    const c1 = BigInt(c1Str);
    const c2 = BigInt(c2Str);

    // 1. Reconstruct the Shared Secret (s):
    // The magic of ElGamal: c1^x mod p is mathematically identical to y^k mod p.
    // We use our private key (x) to unlock it.
    const s    = power(c1, x, p);

    // 2. Calculate the Modular Inverse (s^-1):
    // To "divide" c2 by s to get m, we must multiply by the modular inverse of s.
    // We use Fermat's Little Theorem: s^-1 = s^(p-2) mod p.
    const sInv = power(s, p - 2n, p);

    // 3. Recover the original numerical message (m):
    // m = (c2 * s^-1) mod p
    const m    = (c2 * sInv) % p;

    // 4. Decoding: Convert the numerical BigInt back into a readable UTF-8 string.
    let hex = m.toString(16);

    // Ensure the hex string has an even number of characters before converting to a Buffer
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
