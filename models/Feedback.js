const mongoose = require('mongoose');

const FeedbackSchema = new mongoose.Schema({
    role: { type: String, required: true }, 
    name: { type: String, required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    
    // Encrypted Data Fields
    encryptedEmail: { type: String, required: true },
    emailIv: { type: String, required: true },
    encryptedFeedback: { type: String, required: true },
    feedbackIv: { type: String, required: true },
    
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Feedback', FeedbackSchema);