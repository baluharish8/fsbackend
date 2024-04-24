const mongoose = require('mongoose')

// {serviceimages,name,description,price,location,rating,reviewcontent,isapproved}
const serviceimagesSchema = mongoose.Schema(
    {
        serviceimages: {
            type: String,
            required: [true, "Please enter a serviceimages"]
        },
        name: {
            type: String,
            required: [true, "Please enter a name"]
        },
        description: {
            type: String,
            required: [true, "Please enter a description"]
        },
        price: {
            type: String,
            required: [true, "Please enter a price"]
        },
        location: {
            type: String,
            required: [true, "Please enter a location"]
        },
        rating: {
            type: String,
            // required: [true, "Please enter a rating"]
        },
        reviewcontent: {
            type: String,
            // required: [true, "Please enter a reviewcontent"]
        },
        isapproved: {
            type: String,
            required: [true, "Please enter a isapproved"]
        },
        category: {
            type: String,
            // required: [true, "Please enter a reviewcontent"]
        },
        vendorId: {
            type: String,
            // required: [true, "Please enter a reviewcontent"]
        },

    },
    {
        timestamps: true
    }
)
const vendorServicesData = mongoose.model("vendorservicesdata", serviceimagesSchema , "vendorservicesdata");

module.exports = vendorServicesData;
