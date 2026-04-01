const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
    // Encrypted Identification
    classification: { type: String, required: true }, 
    classificationIv: { type: String, required: true },
    name: { type: String, required: true }, 
    nameIv: { type: String, required: true },
    
    // Encrypted Data
    rating: { type: String, required: true }, 
    ratingIv: { type: String, required: true },
    encryptedEmail: { type: String, required: true },
    emailIv: { type: String, required: true },
    encryptedFeedback: { type: String, required: true },
    feedbackIv: { type: String, required: true },
    
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Feedback', feedbackSchema);