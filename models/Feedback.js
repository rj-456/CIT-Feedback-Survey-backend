const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
    // Encrypted Identification
    classification: { type: String, required: true }, 
    classificationIv: { type: String, required: true },
    
    // Made optional
    name: { type: String, required: false }, 
    nameIv: { type: String, required: false },
    
    // Encrypted Data
    rating: { type: String, required: true }, 
    ratingIv: { type: String, required: true },
    
    // Made optional
    encryptedEmail: { type: String, required: false },
    emailIv: { type: String, required: false },
    
    encryptedFeedback: { type: String, required: true },
    feedbackIv: { type: String, required: true },
    
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Feedback', feedbackSchema);