const mongoose = require('mongoose')

const vendordataSchema = mongoose.Schema(
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
        refreshToken: {
            type: String,
            // required: [false, "Please enter a refreshToken"]
        },
        lastActivity: {
            type:Date,
        },
    },
    {
        timestamps: true
    }
)
const VendorData = mongoose.model('vendordata', vendordataSchema, 'vendordata'); // here using third parameter to send existing collection to avoid cteation of new collection

module.exports = VendorData;
