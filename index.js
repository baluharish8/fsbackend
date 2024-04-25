const express = require('express')
const mongoose = require('mongoose')
const adminData = require('./models/admindata')
const googleAdmin = require('./models/googleadmin')
const VendorData = require('./models/mvmodels')
const ServiceData = require('./models/vendorservicesdata')
const jwtRefreshFile = require('./jwtRefreshToken')
const session = require('express-session');
const app = express()
const cookieParser = require('cookie-parser');
const cors = require('cors');
const corsOptions = {
    origin: 'http://localhost:3009', // Allow requests from this origin
    credentials: true, // Allow cookies to be sent with the request
};
const axios = require('axios');
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
const jwtAuthorization = require('./jwtmiddleware');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
// here db_con variable is a file name
const dotenv = require("dotenv");
dotenv.config();
let bodyParser = require("body-parser")
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
const nodemailer = require("nodemailer");
const authRoutes = require('./routes/auth');
const userAccountVerify = require('./routes/userAccountVerify');
const analytics = require('./routes/analytics');
//Oauth google
const passport = require('passport')
let GoogleStrategy = require('passport-google-oauth20').Strategy;
const ip = require('ip');
const net = require('net');
app.use(session({
    secret: 'googlesecretkey', // Replace with a secret key for session encryption
    resave: false,
    saveUninitialized: true
}));
// Add Passport.js middleware after express-session
app.use(passport.initialize());
app.use(passport.session());
// const { Vonage } = require('@vonage/server-sdk')



app.use('/', authRoutes);
app.use('/', userAccountVerify);
app.use('/', analytics);



app.get("/getvendordata", jwtAuthorization, async (req, res) => {
    let data = await VendorData.find({})
    if (!data) {
        return res.status(400).send('Vendor Data Not Found');
    }
    return res.json(data);

})

app.get("/getservicedata", jwtAuthorization, async (req, res) => {
    let data = await ServiceData.find({})
    if (!data) {
        return res.status(400).send('Service Data Not Found');
    }
    return res.json(data);

})

app.get("/getservice", async (req, res) => {
    let data = await ServiceData.find({})
    if (!data) {
        return res.status(400).send('Service Data Not Found');
    }
    return res.json(data);

})


// refreshtoken
app.get('/refresh', jwtRefreshFile.handleRefreshToken)




mongoose.set("strictQuery", false)
mongoose.
    connect(process.env.MONGODB_CONNECTION)
    .then(() => {
        console.log('connected to MongoDB')
        app.listen(4006, () => {
            console.log(`Node API app is running on port 4006`)
        });
    }).catch((error) => {
        console.log(error)
    })

