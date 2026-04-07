const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
    classification: {
        c1: { type: String, required: true },
        c2: { type: String, required: true }
    },
    name: {
        c1: { type: String, required: false, default: '' },
        c2: { type: String, required: false, default: '' }
    },
    rating: {
        c1: { type: String, required: true },
        c2: { type: String, required: true }
    },
    encryptedEmail: {
        c1: { type: String, required: false, default: '' },
        c2: { type: String, required: false, default: '' }
    },
    encryptedFeedback: {
        c1: { type: String, required: true },
        c2: { type: String, required: true }
    },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Feedback', feedbackSchema);