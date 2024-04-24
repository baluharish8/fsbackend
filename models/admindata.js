const mongoose = require('mongoose')

const adminDataSchema = mongoose.Schema(
    {
        email: {
            type: String,
            required: [true, "Please enter a email"]
        },
        firstName: {
            type: String,
            required: [true, "Please enter a firstName"]
        },
        lastName: {
            type: String,
            required: [true, "Please enter a lastName"]
        },
        password: {
            type: String,
            required: [true, "Please enter a password"]
        },
        initializationVector: {
            type: String,
            required: [true, "Please enter a initializationVector"]
        },
        passwordIv: {
            type: String,
            required: [true, "Please enter a password initializationVector"]
        },
        isAdminVerified: {
            type:Boolean,
            required: [true, "Please enter a password"]
        },
        refreshToken: {
            type: String,
            // required: [false, "Please enter a refreshToken"]
        },
        otp: {
            type: String,
            // required: [false, "Please enter a refreshToken"]
        },
        verifyLinkToken: {
            type: String,
            // required: [false, "Please enter a refreshToken"]
        },
        forgetPasswordLinkToken: {
            type: String,
            // required: [false, "Please enter a refreshToken"]
        },
        loginAttempts: {
             type: Number, 
             default: 0 
            // required: [false, "Please enter a refreshToken"]
        },
        ipAddress: [{
            // Example: an array of strings
            type: String
        }]
    },
    {
        timestamps: true
    }
)
const adminData = mongoose.model('adminData', adminDataSchema, 'adminData'); // here using third parameter to send existing collection to avoid cteation of new collection

module.exports = adminData;
