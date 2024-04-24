const mongoose = require('mongoose')
const googleAdminSchema = mongoose.Schema(
    {
        googleId: {
            type: String,
            required: [true, "Please enter a googleId"]
        },
        displayName:{
            type: String,
            // required: [true, "Please enter a displayName"]
        },
        firstName:{
            type: String,
            // required: [true, "Please enter a displayName"]
        },
        lastName:{
            type: String,
            // required: [true, "Please enter a displayName"]
        },
        email:{
            type: String,
            // required: [true, "Please enter a email"]
        },
        image:{
            type: String,
            // required: [true, "Please enter a image"]
        }
    },
    {
        timestamps:true
    }
)

const GoogleAdminData = mongoose.model('GoogleAdminData',googleAdminSchema,'GoogleAdminData')
module.exports =GoogleAdminData