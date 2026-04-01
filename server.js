require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto'); // Node.js built-in library for cryptographic functions
const jwt = require('jsonwebtoken');
const cors = require('cors');
const Feedback = require('./models/Feedback');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));
app.use(express.static('public'));

/* =========================================================================
   CRYPTOGRAPHY SETUP: AES-256-CBC
   =========================================================================
   AES (Advanced Encryption Standard) is a symmetric encryption algorithm.
   - '256' means it uses a 256-bit (32-byte) key, providing military-grade security.
   - 'cbc' (Cipher Block Chaining) is a mode of operation where each block of 
     plaintext is XORed with the previous ciphertext block before being encrypted. 
     This requires an Initialization Vector (IV) to start the chain.
========================================================================= */
const ALGORITHM = 'aes-256-cbc';

// The master key is loaded from the hidden .env file.
// For AES-256, this key MUST be exactly 32 bytes (256 bits) long.
const AES_KEY = Buffer.from(process.env.AES_KEY, 'utf8');

/**
 * Encrypts plaintext data using AES-256-CBC.
 * @param {string} text - The readable plaintext data to encrypt.
 * @returns {object} An object containing the generated IV and the encrypted ciphertext (both in hex format).
 */
function encryptAES(text) {
    // 1. Generate a random Initialization Vector (IV).
    // The IV must be exactly 16 bytes for AES. It ensures that encrypting the 
    // same text multiple times results in completely different ciphertexts every time.
    const iv = crypto.randomBytes(16);

    // 2. Create the Cipher instance using the algorithm, the master key, and the random IV.
    const cipher = crypto.createCipheriv(ALGORITHM, AES_KEY, iv);

    // 3. Process the plaintext. 'utf8' is the input format, 'hex' is the output format.
    let encrypted = cipher.update(text, 'utf8', 'hex');

    // 4. Finalize the encryption (pads the data if necessary to fit the block size).
    encrypted += cipher.final('hex');

    // Return the IV and the encrypted data as hexadecimal strings so they can be safely stored in MongoDB.
    return { iv: iv.toString('hex'), encryptedData: encrypted };
}

/**
 * Decrypts hexadecimal ciphertext back into readable plaintext.
 * @param {string} encryptedData - The scrambled ciphertext in hex format.
 * @param {string} ivHex - The Initialization Vector (in hex format) originally used to encrypt this specific data.
 * @returns {string} The original readable plaintext.
 */
function decryptAES(encryptedData, ivHex) {
    // 1. Convert the IV from a hex string back into a raw Buffer.
    const iv = Buffer.from(ivHex, 'hex');

    // 2. Create the Decipher instance using the same algorithm, master key, and the specific IV.
    const decipher = crypto.createDecipheriv(ALGORITHM, AES_KEY, iv);

    // 3. Process the ciphertext. 'hex' is the input format, 'utf8' is the desired output format.
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');

    // 4. Finalize the decryption (removes block padding).
    decrypted += decipher.final('utf8');

    return decrypted;
}

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// =========================================================================
// API ROUTES
// =========================================================================

// 1. Submit Feedback (Encrypts ALL fields before saving to DB)
app.post('/api/feedback', async (req, res) => {
    try {
        const { classification, name, email, rating, feedbackText } = req.body;     
        
        // Encrypt each piece of data individually. 
        // This generates a unique IV and Ciphertext for every single field.
        const encClassification = encryptAES(classification);
        const encName = encryptAES(name);
        const encRating = encryptAES(rating.toString()); // Convert numbers to strings before encrypting
        const encEmail = encryptAES(email);
        const encFeedback = encryptAES(feedbackText);

        // Store only the hex ciphertext and the IVs in the database. 
        // The raw plaintext NEVER touches the database.
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

// 2. Admin Login (Generates JWT Session Token)
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
        // Issue a secure token valid for 1 hour to prevent unauthorized access
        const token = jwt.sign({ classification: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// 3. Get Encrypted Dashboard Data
// Fetches the raw ciphertext from the database and sends it to the frontend WITHOUT decrypting it.
app.get('/api/admin/feedbacks', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'No token provided' });
    try {
        jwt.verify(token, process.env.JWT_SECRET); // Verify admin session
        const feedbacks = await Feedback.find().sort({ createdAt: -1 });
        
        // Map database response to strictly send encrypted strings
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

// 4. On-Demand Decryption (Decrypts a specific record when requested)
app.post('/api/admin/decrypt/:id', async (req, res) => {
    const token = req.headers['authorization'];
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        const f = await Feedback.findById(req.params.id);
        
        // Retrieve the ciphertext and its matching IV from the database,
        // run them through the decryption function, and return the plaintext.
        res.json({
            classification: decryptAES(f.classification, f.classificationIv),
            name: decryptAES(f.name, f.nameIv),
            rating: decryptAES(f.rating, f.ratingIv),
            email: decryptAES(f.encryptedEmail, f.emailIv),
            message: decryptAES(f.encryptedFeedback, f.feedbackIv)
        });
    } catch (error) { res.status(500).json({ error: 'Decryption failed' }); }
});

// 5. Delete Feedback Record
app.delete('/api/admin/feedback/:id', async (req, res) => {
    const token = req.headers['authorization'];
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        await Feedback.findByIdAndDelete(req.params.id);
        res.json({ message: 'Deleted' });
    } catch (error) { res.status(401).json({ error: 'Unauthorized' }); }
});

app.listen(3000, () => console.log('Backend running on port 3000'));