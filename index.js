const express = require('express')
const mongoose = require('mongoose')
const adminData = require('./models/admindata')
const googleAdmin = require('./models/googleadmin')
const VendorData = require('./models/mvmodels')
const ServiceData = require('./models/vendorservicesdata')
const { SearchQuery, Click, View, Session } = require('./models/analyticsdb')

const jwtRefreshFile = require('./jwtRefreshToken')
const session = require('express-session');
const app = express()
const cookieParser = require('cookie-parser');
const cors = require('cors');
const corsOptions = {
    origin: 'http://localhost:3009', // Allow requests from this origin
    credentials: true, // Allow cookies to be sent with the request
};
const fast2sms = require('fast-two-sms')
var unirest = require("unirest");
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
const crypto = require("crypto"); // for data encryption
const bcrypt = require('bcryptjs'); // for password hashing
//post data decoded
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
const otpGenerator = require('otp-generator');
const nodemailer = require("nodemailer");

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

const { Vonage } = require('@vonage/server-sdk')


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
//data analytics start
app.post('/search', async (req, res) => {
    const query = req.body.query; // Get search query from request body
    console.log(req.body.query)
    try {
        // Log the search query to MongoDB
        await SearchQuery.create({ query });

        // Return search results to the user
        res.sendStatus(200);

    } catch (error) {
        console.error('Error logging search query:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/getsearchcount', async (req, res) => {
    try {
        const activeUsersCount = await SearchQuery.countDocuments({});
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/analytics/popular-searches', async (req, res) => {
    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await SearchQuery.aggregate([
            { $group: { _id: '$query', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        // const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // // Fetch all documents corresponding to the IDs
        // let data = await ServiceData.find({ _id: { $in: ids } });
        // // console.log(data.length, 'click ids data')

        // const mergedClicksData = [];
        // for (let i = 0; i < popularItems.length; i++) {
        //     const popularItemId = popularItems[i]._id;
        //     console.log(popularItemId, 'popularItemId')
        //     const count = popularItems[i].count;
        //     console.log(data[i]._id, 'servicesids')

        //     const matchingDataItem = data.find(item => item.id === popularItemId);

        //     if (matchingDataItem) {
        //         const item = {
        //             _id: popularItemId,
        //             count: count,
        //             name: matchingDataItem.name // Additional data from data array matching the ID
        //         };

        //         mergedClicksData.push(item);
        //     } else {
        //         console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
        //     }
        // }
        // console.log(mergedData,'mergedData')
        res.json(popularItems);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Express middleware to log clicks
app.post('/click', async (req, res) => {
    const { itemId } = req.body; // Get ID of the clicked item

    try {
        // Log the click event to MongoDB
        await Click.create({ itemId });
        res.sendStatus(200);
    } catch (error) {
        console.error('Error logging click event:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/getclickcount', async (req, res) => {
    try {
        const activeUsersCount = await Click.countDocuments({});
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/analytics/popular-clicks', async (req, res) => {
    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await Click.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data.length, 'click ids data')

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data[i].id, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name // Additional data from data array matching the ID
                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }

        // console.log(mergedData,'mergedData')
        res.json(mergedClicksData);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/analytics/vendor/popular-clicks', async (req, res) => {
    const { _id } = req.body
    console.log('from vendoritemcllicks vendorId', _id)
    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await Click.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data[1].category,data[1].vendorId, 'click ids data')
        console.log(data.length, 'from service data length')
        // const filteredItems = data.filter(item => console.log(item.category,item.vendorId,item.name));

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            // console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name, // Additional data from data array matching the ID
                    vendorId: matchingDataItem.vendorId
                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }


        const filteredVendoritemClicks = mergedClicksData.filter(item => item.vendorId === _id);

        // console.log(mergedData,'mergedData')
        // console.log(mergedClicksData,'vendorItemsClicks')
        console.log(filteredVendoritemClicks, 'filteredVendoritemClicks')

        res.json(filteredVendoritemClicks);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Express middleware to log views
app.post('/view', async (req, res) => {
    const { itemId, category } = req.body; // Get ID of the viewed item

    try {
        // Log the view event to MongoDB
        await View.create({ itemId, categories: category });
        res.sendStatus(200);
    } catch (error) {
        console.error('Error logging view event:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/getviewcount', async (req, res) => {
    try {
        const activeUsersCount = await View.countDocuments({});
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/analytics/popular-views', async (req, res) => {
    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await View.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data.length, 'click ids data')

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data[i].id, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name, // Additional data from data array matching the ID

                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }
        // console.log(mergedData,'mergedData')
        res.json(mergedClicksData);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.post('/analytics/vendor/popular-views', async (req, res) => {
    const { _id } = req.body

    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await View.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data.length, 'click ids data')

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data[i].id, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name, // Additional data from data array matching the ID
                    vendorId: matchingDataItem.vendorId

                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }
        const filteredVendoritemViews = mergedClicksData.filter(item => item.vendorId === _id);

        // console.log(mergedData,'mergedData')
        console.log(filteredVendoritemViews, 'filteredVendoritemViews')

        res.json(filteredVendoritemViews);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Express route to handle tracking popular categories
app.get('/analytics/popular-categories', async (req, res) => {
    try {
        // Perform aggregation to get the most popular categories
        const popularCategories = await View.aggregate([
            { $group: { _id: '$categories', count: { $sum: 1 } } }, // Group by categories
            { $sort: { count: -1 } }, // Sort by count in descending order
            { $limit: 10 } // Limit to top 10 categories
        ]);

        res.json(popularCategories);
    } catch (error) {
        console.error('Error fetching popular categories:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.post('/sendsessionduration', async (req, res) => {
    const { duration, _id } = req.body; // Get ID of the viewed item

    try {
        // Log the view event to MongoDB
        let data = await Session.create({ duration });
        if (data) {
            await VendorData.findByIdAndUpdate(_id, { lastActivity: Date.now() - 2 * 60 * 1000 });

        }
        res.sendStatus(200);
    } catch (error) {
        console.error('Error logging view event:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/analytics/average-session-duration', async (req, res) => {
    try {
        const averageSessionDuration = await Session.aggregate([
            { $group: { _id: null, totalDuration: { $sum: '$duration' }, count: { $sum: 1 } } }, // Calculate total duration and count of sessions
            { $project: { _id: 0, averageDuration: { $divide: ['$totalDuration', '$count'] } } } // Calculate average duration
        ]);

        res.json(averageSessionDuration[0]); // Return the result
    } catch (error) {
        console.error('Error fetching average session duration:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//data analytics end


// Nodemailer transporter

// var transporter = nodemailer.createTransport({
//     service: 'gmail',
//     auth: {
//       user: 'harishnidigonda8@gmail.com',
//       pass: 'mbjrghbnzrhbvavy'
//     }
//   });

//   var mailOptions = {
//     from: 'harishnidigonda8@gmail.com',
//     to: 'baluharish8@gmail.com',
//     subject: 'Sending Email using Node.js',
//     text: 'That was easy!'
//   };

//   transporter.sendMail(mailOptions, function(error, info){
//     if (error) {
//       console.log(error);
//     } else {
//       console.log('Email sent: ' + info.response);
//     }
//   });


let transporter = nodemailer.createTransport({
    service: process.env.SENT_HOST,
    auth: {
        user: process.env.SENT_EMAIL,
        pass: process.env.SENT_PASSWORD
    }
});

app.post("/mobileotpsend", jwtAuthorization, async (req, res) => {
    let email;
    try {
        let data = await adminData.findOne({ _id: req.user.id });
        if (!data) {
            return res.status(404).json({ message: 'User Not found' });
        }
        email = data.email
    } catch (error) {

    }
    console.log(email);

    const otp = generateOTP();
    const vonage = new Vonage({
        apiKey: "9f3f709c",
        apiSecret: "SEYrhS4xQp8hclYx"
    })
    const from = "Vonage APIs"
    const to = "919676918847"
    const text = otp
    async function sendSMS() {
        await vonage.sms.send({ to, from, text })
            .then(async resp => {
                console.log('Message sent successfully'); console.log(resp);
                await adminData.findOneAndUpdate({ _id: req.user.id }, { otp: otp }, { new: true });
                return res.status(200).json({ message: 'OTP send successfully' });

            })
            .catch(err => {
                console.log('There was an error sending the messages.'); console.error(err);

                return res.status(500).send('Server Error')

            }
            );
    }

    sendSMS();
})

app.post("/otpsend", jwtAuthorization, async (req, res) => {
    let email;
    try {
        let data = await adminData.findOne({ _id: req.user.id });
        if (!data) {
            return res.status(404).json({ message: 'User Not found' });
        }
        email = data.email
    } catch (error) {

    }
    console.log(email);

    const otp = generateOTP();


    let mailOptions = {
        from: process.env.SENT_EMAIL,
        to: email,
        subject: "Verify otp",
        text: `Your OTP is: ${otp}`,
    };

    transporter.sendMail(mailOptions, async function (error, info) {
        if (error) {
            console.log(error);
        } else {
            console.log("Email sent successfully!");
            await adminData.findOneAndUpdate({ _id: req.user.id }, { otp: otp }, { new: true });
            return res.status(200).json({ message: 'OTP send successfully' });

        }
    });
})
function generateOTP() {

    const digitChars = '0123456789';

    // Generate a 6-digit OTP using only numeric characters
    // const otp = otpGenerator.generate(6);

    const otp = Math.floor(100000 + Math.random() * 900000);
    console.log('Generated OTP:', otp);
    return otp
}

app.post("/otpverify", jwtAuthorization, async (req, res) => {
    console.log(req.user, "from req");

    try {
        let data = await adminData.findOne({ _id: req.user.id });
        console.log(data, "from admindb data");

        if (!data) {
            return res.status(404).json({ message: 'User Not found' });
        }

        console.log(data.otp, "from google data", req.body.otp);

        if (req.body.otp == data.otp) {
            console.log("OTP verification success");
            return res.status(200).json({ message: 'OTP verification successful' });
        } else {
            console.log("OTP verification failed");
            return res.status(404).json({ message: 'OTP verification failed' });
        }
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post("/registration1", async (req, res) => {
    console.log(req.body.password, 'req.body.password')
    if (req.body.adminKey !== "adminkey") {

        return res.status(400).send({ message: 'key not valid' });
    }
    let checked
    try {
        checked = await adminData.findOne({ email: req.body.email })

    } catch (err) {
        console.log(err)
    }
    if (checked) {
        return res.status(400).send({ message: 'User already exists' });
    } else {
        const iv = crypto.randomBytes(16);
        const passwordIv = crypto.randomBytes(16);

        const key = process.env.CRYPTO_ENCRYPTION_KEY;
        const cipherFirstName = crypto.createCipheriv('aes-256-cbc', key, iv);
        let firstNameEncrypted = cipherFirstName.update(req.body.firstName, 'utf8', 'hex');
        firstNameEncrypted += cipherFirstName.final('hex');

        const cipherLastName = crypto.createCipheriv('aes-256-cbc', key, iv);
        let lastNameEncrypted = cipherLastName.update(req.body.lastName, 'utf8', 'hex');
        lastNameEncrypted += cipherLastName.final('hex');

        const cipherPassword = crypto.createCipheriv('aes-256-cbc', key, passwordIv);
        let passwordEncrypted = cipherPassword.update(req.body.password, 'utf8', 'hex');
        passwordEncrypted += cipherPassword.final('hex');


        // const hashedPassword = bcrypt.hashSync(req.body.password)
        const encryptioniv = iv.toString('base64');
        const encryptionPasswordIv = passwordIv.toString('base64');


        const postData = await adminData.create({
            email: req.body.email,
            firstName: firstNameEncrypted,
            lastName: lastNameEncrypted,
            password: passwordEncrypted,
            isAdminVerified: false,
            initializationVector: encryptioniv,
            passwordIv: encryptionPasswordIv
        });
        if (!postData) {
            return res.status(400).send('User Not Saved');

        }
        console.log(postData, 'from postdata 157')
        console.log(postData.id, 'from postdata id 158')

        let payload = {
            user: {
                id: postData.id
            }
        }
        const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
        const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });

        try {
            const updatedUserData = await adminData.findOneAndUpdate({ _id: postData.id }, { refreshToken: refreshToken }, { new: true });
            console.log(updatedUserData + "dbtokencraeteResponse")
        } catch (err) {
            console.log(err)
        }

        token = accessToken
        console.log("AccessToken:" + accessToken)
        console.log("refreshToken:" + refreshToken)
        res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })
        return res.json({ postData, token })
        // res.status(201).json(postData);
    }
})


//jwt start multivendor login


//Admin Login using email
app.post('/login', async (req, res) => {
    //capture the client's original IP address when the request passes through proxies or load balancers.
    const forwardedFor = req.headers['x-forwarded-for'];
    const ipAddress = forwardedFor ? forwardedFor.split(',')[0] : req.socket.remoteAddress;
    console.log(ipAddress + "ipAddress line 289")

    try {
        const { email, password } = req.body;
        console.log(email + password + "from input")
        let checked;
        try {
            checked = await adminData.findOne({ email: req.body.email })
            console.log(checked + "from db")
        } catch (err) {
            console.log(err)
        }
        if (!checked) {
            checked = await VendorData.findOne({ email: req.body.email })
        }

        if (!checked) {
            return res.status(400).send('User Not Found');
        }

        console.log(checked.email, 'checked.email')
        await adminData.findOneAndUpdate({ email: checked.email }, { $push: { ipAddress: ipAddress } }, { new: true });

        if (checked) {
            const encryptioniv = Buffer.from(checked.initializationVector, 'base64');
            const key = process.env.CRYPTO_ENCRYPTION_KEY;
            const decipherFirstName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
            const decipherLastName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
            let firstNameDecrypted = decipherFirstName.update(checked.firstName, 'hex', 'utf8');
            firstNameDecrypted += decipherFirstName.final('utf8');
            let lastNameDecrypted = decipherLastName.update(checked.lastName, 'hex', 'utf8');
            lastNameDecrypted += decipherLastName.final('utf8');
            console.log(firstNameDecrypted + "" + lastNameDecrypted)
            // bcrypt
            console.log(checked.password, 'checked.password')
            let passwordCheck;
            if (checked.passwordIv) {

                const passwordEncryptioniv = Buffer.from(checked.passwordIv, 'base64');
                const decipherPassword = crypto.createDecipheriv('aes-256-cbc', key, passwordEncryptioniv);
                let passwordDecrypted = decipherPassword.update(checked.password, 'hex', 'utf8');
                passwordDecrypted += decipherPassword.final('utf8');

                passwordCheck = password === passwordDecrypted
            } else {
                passwordCheck = bcrypt.compareSync(password, checked.password)

            }

            console.log(passwordCheck + " : " + "from bcrypt 335")
            if (!passwordCheck) {
                return res.status(400).send('Password Not Valid');
            }
        }

        console.log(checked.isAdminVerified)
        if (!checked.isAdminVerified) {

            console.log(checked.id, 'line 271 checked id')
            let payload = {
                user: {
                    id: checked.id
                }
            }
            const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
            const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
            try {
                const updatedUserData = await adminData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken }, { new: true });
                console.log(updatedUserData + "dbtokencraeteResponse")
            } catch (err) {
                console.log(err)
            }
            token = accessToken
            console.log("AccessToken:" + accessToken)
            console.log("refreshToken:" + refreshToken)
            res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })


            // return res.status(400).send('User Not verified');
            // return res.json({ token }).status(400).send('User Not verified');
            return res.status(400).json({ message: 'User Not verified', token });


        }
        const otp = generateOTP();

        console.log("checked.email:" + checked.email)

        let transporter = nodemailer.createTransport({
            service: process.env.SENT_HOST,
            auth: {
                user: process.env.SENT_EMAIL,
                pass: process.env.SENT_PASSWORD
            }
        });
        let mailOptions = {
            from: process.env.SENT_EMAIL,
            to: checked.email,
            subject: "Verify otp",
            text: `Your OTP is: ${otp}`,
        };
        // const vonage = new Vonage({
        //     apiKey: "9f3f709c",
        //     apiSecret: "SEYrhS4xQp8hclYx"
        //   })
        //   const from = "Vonage APIs"
        //   const to = "919676918847"
        //   const text = otp

        //   async function sendSMS() {
        //       await vonage.sms.send({to, from, text})
        //           .then(async resp => {
        //             console.log('Message sent successfully'); console.log(resp);
        //             let payload = {
        //                 user: {
        //                     id: checked.id
        //                 }
        //             }
        //             const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
        //             const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
        //             try {
        //                 const updatedUserData = await adminData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken, otp: otp }, { new: true });
        //                 console.log(updatedUserData + "dbtokencraeteResponse")
        //             } catch (err) {
        //                 console.log(err)
        //             }
        //             token = accessToken
        //             console.log("AccessToken:" + accessToken)
        //             console.log("refreshToken:" + refreshToken)
        //             // console.log("  checked.loginAttempts",  checked.loginAttempts+1);
        //             await adminData.findOneAndUpdate({ email: checked.email }, { loginAttempts: checked.loginAttempts+1}, { new: true });
        //             res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })
        //             // res.set('Authorization', `Bearer ${accessToken}`); not working while verifying
        //             return res.json({ checked, token })

        //          })
        //           .catch(err => {
        //             console.log('There was an error sending the messages.'); console.error(err); 

        //         return res.status(500).send('Server Error')

        //             }
        //              );
        //   }

        //   sendSMS();

        transporter.sendMail(mailOptions, async function (error, info) {
            if (error) {
                console.log(error);
                return res.status(500).send('Server Error')

            } else {
                let payload = {
                    user: {
                        id: checked.id
                    }
                }
                const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
                const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
                try {
                    const updatedUserData = await adminData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken, otp: otp }, { new: true });
                    console.log(updatedUserData + "dbtokencraeteResponse")
                } catch (err) {
                    console.log(err)
                }
                token = accessToken
                console.log("AccessToken:" + accessToken)
                console.log("refreshToken:" + refreshToken)
                // console.log("  checked.loginAttempts",  checked.loginAttempts+1);
                await adminData.findOneAndUpdate({ email: checked.email }, { loginAttempts: checked.loginAttempts + 1 }, { new: true });
                res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })
                // res.set('Authorization', `Bearer ${accessToken}`); not working while verifying
                console.log("Email sent successfully!");
                return res.json({ checked, token })


            }
        });
    }
    catch (err) {
        console.log(err);
        return res.status(500).send('Server Error')
    }
})

//vendor login
app.post('/vendorlogin', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(email + password + "from input")

        // let data = await db_con.getRegistrationData();
        // let checked = data.find(user => user.email == email)
        let checked;
        try {
            checked = await VendorData.findOne({ email: req.body.email })
            console.log(checked + "from db")

        } catch (err) {
            console.log(err)
        }

        if (checked) {
            // const iv = crypto.randomBytes(16);
            // Retrieve encryptionivBase64 from the database
            const encryptioniv = Buffer.from(checked.initializationVector, 'base64');
            const key = process.env.CRYPTO_ENCRYPTION_KEY;
            // const decipher = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
            // let decrypted = decipher.update(checked.password, 'hex', 'utf8');
            // decrypted += decipher.final('utf8');
            // console.log(decrypted)
            const decipherFirstName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
            const decipherLastName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
            let firstNameDecrypted = decipherFirstName.update(checked.firstName, 'hex', 'utf8');
            firstNameDecrypted += decipherFirstName.final('utf8');
            let lastNameDecrypted = decipherLastName.update(checked.lastName, 'hex', 'utf8');
            lastNameDecrypted += decipherLastName.final('utf8');
            console.log(firstNameDecrypted + "" + lastNameDecrypted)


            // bcrypt
            const passwordCheck = bcrypt.compareSync(password, checked.password)
            console.log(passwordCheck + "" + "from bcrypt")
            if (!passwordCheck) {
                return res.status(400).send('Invalid credentials');
            }
        }
        if (!checked) {
            return res.status(400).send('User Not Found');
        }

        let payload = {
            user: {
                id: checked.id
            }
        }

        const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE }
            // (err, token) => {
            //     if (err) throw err;
            //     // const removedPasswordData={...checked}
            //     // delete removedPasswordData.password
            //     // return res.json({removedPasswordData, token })
            //     return res.json({ checked, token })

            // }
        )

        const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });

        try {
            // const dbtoken = await VendorData.findOne({refreshToken})
            // if(!dbtoken){
            //     console.log(dbtoken+"dbtoken")
            // const data = await VendorData.create({refreshToken:refreshToken})
            const updatedVendorData = await VendorData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken }, { new: true });

            console.log(updatedVendorData + "dbtokencraeteResponse")

            // }else{
            //     console.log("not null valuefromdbtoken")

            // }

        } catch (err) {
            console.log(err)
        }


        token = accessToken
        console.log("AccessToken:" + accessToken)
        console.log("refreshToken:" + refreshToken)
        res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })
        // res.set('Authorization', `Bearer ${accessToken}`); not working while verifying
        await VendorData.findByIdAndUpdate(checked.id, { lastActivity: Date.now() });
        return res.json({ checked, token })

    }
    catch (err) {
        console.log(err);
        return res.status(500).send('Server Error')
    }
})

// Get active users count route
app.get('/activeuserscount', async (req, res) => {
    try {
        const activeUsersCount = await VendorData.countDocuments({ lastActivity: { $gt: new Date(Date.now() - 2 * 60 * 1000) } });
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//Admin login using Mobile number otp working
// app.post('/login', async (req, res) => {
//     //capture the client's original IP address when the request passes through proxies or load balancers.
//     const forwardedFor = req.headers['x-forwarded-for'];
//     const ipAddress = forwardedFor ? forwardedFor.split(',')[0] : req.socket.remoteAddress;
//      console.log(ipAddress + "ipAddress line 289")

//     try {
//         const { email, password } = req.body;
//         console.log(email + password + "from input")
//         let checked;
//         try {
//             checked = await adminData.findOne({ email: req.body.email })
//             console.log(checked + "from db")
//         } catch (err) {
//             console.log(err)
//         }
//         if (!checked) {
//             return res.status(400).send('User Not Found');
//         }

//         console.log(checked.email,'checked.email')
//         await adminData.findOneAndUpdate({ email: checked.email }, { $push: { ipAddress: ipAddress } }, { new: true });

//         if (checked) {
//             const encryptioniv = Buffer.from(checked.initializationVector, 'base64');
//             const key = process.env.CRYPTO_ENCRYPTION_KEY;
//             const decipherFirstName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
//             const decipherLastName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
//             let firstNameDecrypted = decipherFirstName.update(checked.firstName, 'hex', 'utf8');
//             firstNameDecrypted += decipherFirstName.final('utf8');
//             let lastNameDecrypted = decipherLastName.update(checked.lastName, 'hex', 'utf8');
//             lastNameDecrypted += decipherLastName.final('utf8');
//             console.log(firstNameDecrypted + "" + lastNameDecrypted)
//             // bcrypt
//             console.log(checked.password,'checked.password')
//             const passwordEncryptioniv = Buffer.from(checked.passwordIv, 'base64');
//             const decipherPassword = crypto.createDecipheriv('aes-256-cbc', key, passwordEncryptioniv);
//             let passwordDecrypted = decipherPassword.update(checked.password, 'hex', 'utf8');
//             passwordDecrypted += decipherPassword.final('utf8');

//             // const passwordCheck = bcrypt.compareSync(password, checked.password)
//             const passwordCheck =password=== passwordDecrypted
//             console.log(passwordCheck + "" + "from bcrypt")
//             if (!passwordCheck) {
//                 return res.status(400).send('Password Not Valid');
//             }
//         }

//       console.log(checked.isAdminVerified)
//         if(!checked.isAdminVerified){

//             console.log(checked.id,'line 271 checked id')
//             let payload = {
//                 user: {
//                     id: checked.id
//                 }
//             }
//             const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
//             const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
//             try {
//                 const updatedUserData = await adminData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken}, { new: true });
//                 console.log(updatedUserData + "dbtokencraeteResponse")
//             } catch (err) {
//                 console.log(err)
//             }
//             token = accessToken
//             console.log("AccessToken:" + accessToken)
//             console.log("refreshToken:" + refreshToken)
//             res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })


//             // return res.status(400).send('User Not verified');
//             // return res.json({ token }).status(400).send('User Not verified');
//             return res.status(400).json({ message: 'User Not verified', token });


//         }
//         const otp = generateOTP();

//         console.log("checked.email:" + checked.email)

//         let transporter = nodemailer.createTransport({
//             service: process.env.SENT_HOST,
//             auth: {
//                 user: process.env.SENT_EMAIL,
//                 pass: process.env.SENT_PASSWORD
//             }
//         });
//         let mailOptions = {
//             from: process.env.SENT_EMAIL,
//             to: checked.email,
//             subject: "Verify otp",
//             text: `Your OTP is: ${otp}`,
//         };
//         const vonage = new Vonage({
//             apiKey: "9f3f709c",
//             apiSecret: "SEYrhS4xQp8hclYx"
//           })
//           const from = "Vonage APIs"
//           const to = "919676918847"
//           const text = otp

//           async function sendSMS() {
//               await vonage.sms.send({to, from, text})
//                   .then(async resp => {
//                     console.log('Message sent successfully'); console.log(resp);
//                     let payload = {
//                         user: {
//                             id: checked.id
//                         }
//                     }
//                     const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
//                     const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
//                     try {
//                         const updatedUserData = await adminData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken, otp: otp }, { new: true });
//                         console.log(updatedUserData + "dbtokencraeteResponse")
//                     } catch (err) {
//                         console.log(err)
//                     }
//                     token = accessToken
//                     console.log("AccessToken:" + accessToken)
//                     console.log("refreshToken:" + refreshToken)
//                     // console.log("  checked.loginAttempts",  checked.loginAttempts+1);
//                     await adminData.findOneAndUpdate({ email: checked.email }, { loginAttempts: checked.loginAttempts+1}, { new: true });
//                     res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })
//                     // res.set('Authorization', `Bearer ${accessToken}`); not working while verifying
//                     return res.json({ checked, token })

//                  })
//                   .catch(err => {
//                     console.log('There was an error sending the messages.'); console.error(err); 

//                 return res.status(500).send('Server Error')

//                     }
//                      );
//           }

//           sendSMS();
//     }
//     catch (err) {
//         console.log(err);
//         return res.status(500).send('Server Error')
//     }
// })




//Admin another mobile number otp not working asking payments
// app.post('/login', async (req, res) => {
//     // let options = {authorization : process.env.FAST2SMS_API_KEY , message : 'testmessage' ,  numbers : ['8341948848']} 
//     // fast2sms.sendMessage(options)
//     // .then((res)=>{
//     // console.log(res,res.data, 'fasttwo sms success line 365')
//     // })
//     // .catch((error)=>{
//     //     console.log(error, 'fasttoerror')

//     // })


// // var req = unirest("GET", "https://www.fast2sms.com/dev/bulkV2");

// // req.query({
// //   "authorization": process.env.FAST2SMS_API_KEY,
// //   "variables_values": "5599",
// //   "route": "otp",
// //   "numbers": "9676918847"
// // });

// // req.headers({
// //   "cache-control": "no-cache"
// // });


// // req.end(function (res) {
// //   if (res.error) throw new Error(res.error);

// //   console.log(res.body);
// // });


// // Fast2SMS API credentials
// // const apiKey = 'YOUR_FAST2SMS_API_KEY';
// // const senderId = 'SENDER_ID'; // Your sender ID (optional)

// // Fast2SMS API endpoint for sending SMS
// const apiUrl = 'https://www.fast2sms.com/dev/bulkV2';

// // Function to send SMS
// async function sendSMS() {
//     try {
//         const response = await axios.post(apiUrl, {
//             // sender_id: senderId,
//             message: 'This is a test message from Fast2SMS!',
//             language: 'english',
//             route: 'p', // 'p' for promotional, 't' for transactional
//             numbers: '9676918847' // Comma-separated list of recipient numbers
//         }, {
//             headers: {
//                 Authorization: process.env.FAST2SMS_API_KEY
//             }
//         });

//         console.log('Message sent successfully:', response.data);
//     } catch (error) {
//         console.error('Error sending message:', error.response ? error.response.data : error.message);
//     }
// }

// // Call the function to send SMS
// sendSMS();

//     //capture the client's original IP address when the request passes through proxies or load balancers.
//     // const forwardedFor = req.headers['x-forwarded-for'];
//     // const ipAddress = forwardedFor ? forwardedFor.split(',')[0] : req.socket.remoteAddress;
//     // console.log(ipAddress + "ipAddress line 289")

//     try {
//         const { email, password } = req.body;
//         console.log(email + password + "from input")
//         let checked;
//         try {
//             checked = await adminData.findOne({ email: req.body.email })
//             console.log(checked + "from db")
//         } catch (err) {
//             console.log(err)
//         }
//         if (!checked) {
//             return res.status(400).send('User Not Found');
//         }

//         console.log(checked.email, 'checked.email')
//         await adminData.findOneAndUpdate({ email: checked.email }, { $push: { ipAddress: ipAddress } }, { new: true });

//         if (checked) {
//             const encryptioniv = Buffer.from(checked.initializationVector, 'base64');
//             const key = process.env.CRYPTO_ENCRYPTION_KEY;
//             const decipherFirstName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
//             const decipherLastName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
//             let firstNameDecrypted = decipherFirstName.update(checked.firstName, 'hex', 'utf8');
//             firstNameDecrypted += decipherFirstName.final('utf8');
//             let lastNameDecrypted = decipherLastName.update(checked.lastName, 'hex', 'utf8');
//             lastNameDecrypted += decipherLastName.final('utf8');
//             console.log(firstNameDecrypted + "" + lastNameDecrypted)
//             // bcrypt
//             console.log(checked.password, 'checked.password')
//             const passwordCheck = bcrypt.compareSync(password, checked.password)
//             console.log(passwordCheck + "" + "from bcrypt")
//             if (!passwordCheck) {
//                 return res.status(400).send('Password Not Valid');
//             }
//         }

//         console.log(checked.isAdminVerified)
//         if (!checked.isAdminVerified) {

//             console.log(checked.id, 'line 271 checked id')
//             let payload = {
//                 user: {
//                     id: checked.id
//                 }
//             }
//             const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
//             const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
//             try {
//                 const updatedUserData = await adminData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken }, { new: true });
//                 console.log(updatedUserData + "dbtokencraeteResponse")
//             } catch (err) {
//                 console.log(err)
//             }
//             token = accessToken
//             console.log("AccessToken:" + accessToken)
//             console.log("refreshToken:" + refreshToken)
//             res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })


//             // return res.status(400).send('User Not verified');
//             // return res.json({ token }).status(400).send('User Not verified');
//             return res.status(400).json({ message: 'User Not verified', token });


//         }
//         const otp = generateOTP();

//         console.log("checked.email:" + checked.email)

//         // let transporter = nodemailer.createTransport({
//         //     service: process.env.SENT_HOST,
//         //     auth: {
//         //         user: process.env.SENT_EMAIL,
//         //         pass: process.env.SENT_PASSWORD
//         //     }
//         // });
//         // let mailOptions = {
//         //     from: process.env.SENT_EMAIL,
//         //     to: checked.email,
//         //     subject: "Verify otp",
//         //     text: `Your OTP is: ${otp}`,
//         // };


//         // transporter.sendMail(mailOptions, async function (error, info) {
//             // if (error) {
//             //     console.log(error);
//             //     return res.status(500).send('Server Error')

//             // } else {
//                 //mobile otp strat

// //mobile otp end
//                 let payload = {
//                     user: {
//                         id: checked.id
//                     }
//                 }
//                 const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
//                 const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
//                 try {
//                     const updatedUserData = await adminData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken, otp: otp }, { new: true });
//                     console.log(updatedUserData + "dbtokencraeteResponse")
//                 } catch (err) {
//                     console.log(err)
//                 }
//                 token = accessToken
//                 console.log("AccessToken:" + accessToken)
//                 console.log("refreshToken:" + refreshToken)
//                 // console.log("  checked.loginAttempts",  checked.loginAttempts+1);
//                 await adminData.findOneAndUpdate({ email: checked.email }, { loginAttempts: checked.loginAttempts + 1 }, { new: true });
//                 res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })
//                 // res.set('Authorization', `Bearer ${accessToken}`); not working while verifying
//                 console.log("Email sent successfully!");
//                 return res.json({ checked, token })

//                 // return res.status(200).send('Success')

//             // }
//         // });
//     }
//     catch (err) {
//         console.log(err);
//         return res.status(500).send('Server Error')
//     }
// })
//jwtend

// app.post("/otpverify", jwtAuthorization, async (req, res) => {
//     console.log(req.user, "from req");

//     try {
//         let data = await adminData.findOne({ _id: req.user.id });
//         console.log(data, "from admindb data");

//     if(!data){

//        return res.status(404).json({ message: 'user Not found' });


//     }
//         // console.log(data.otp, "from google data", req.body.otp);

//         if (req.body.otp == data.otp) {
//             console.log("otp verify success");
//             res.status(200).send('testing successful');
//         } else {
//             console.log("otp verify failed");
//             res.status(404).json({ message: 'OTP verification failed' });
//         }
//     } catch (error) {
//         console.error("Error occurred:", error);
//         res.status(500).json({ message: error.message });
//     }
// });



//admin verify
// Generate a random token
function generateToken() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}



// Endpoint to handle verification
//   app.get('/verify', async (req, res) => {
//     const token = req.query.token;
//     const email = req.query.email;
// console.log(email,'378 line')

//     try {

//       const tokenDoc = await adminData.findOne({ email });

//       if (tokenDoc.email===email) {
// console.log(tokenDoc,'380 line token doc')
// await adminData.findOneAndUpdate(
//     { email: email }, 
//     { $unset: { verifyLinkToken: 1 },isAdminVerified:true }, 
//     { new: true }
//   );
//         // Token is valid, mark the user as verified
//         // const email = tokenDoc.value.email;
//         // Perform your database operation to mark the user as verified
//         // For demonstration purposes, just log the email
//         console.log(`User with email ${email} is verified.`);
//         // Redirect to the login page
//         res.redirect('http://localhost:3009/login');
//       } else {
//         // Token is invalid or expired
//         res.send('Invalid token.');
//       }
//     } catch (error) {
//       console.error('Error:', error);
//       res.status(500).send('Internal Server Error');
//     } 
//   });

app.get('/verify', async (req, res) => {
    const token = req.query.token;
    // const email = req.query.email;
    const id = req.query.id;

    console.log(id, '462 line from query verify')

    try {

        const tokenDoc = await adminData.findOne({ _id: id });
        console.log(tokenDoc.id, '490 line token doc')

        if (tokenDoc.id === id) {
            console.log(tokenDoc, '380 line token doc')
            await adminData.findOneAndUpdate(
                { _id: id },
                { $unset: { verifyLinkToken: 1 }, isAdminVerified: true },
                { new: true }
            );
            // Token is valid, mark the user as verified
            // const email = tokenDoc.value.email;
            // Perform your database operation to mark the user as verified
            // For demonstration purposes, just log the email
            console.log(`User with email ${id} is verified.`);
            // Redirect to the login page
            res.redirect('http://localhost:3009/login');
        } else {
            // Token is invalid or expired
            res.send('Invalid token.');
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to initiate email verification
app.post('/sendverification', jwtAuthorization, async (req, res) => {
    const token = generateToken();
    try {

        // Insert token into database
        console.log("415 line req.user.id check:", req.user);
        console.log("Email sent successfully!");
        let data = await adminData.findOneAndUpdate({ _id: req.user.id }, { verifyLinkToken: token }, { new: true });
        if (!data) {
            return res.status(400).send('User Not Found');
        }
        // Send the authorization link via email
        console.log(data.email, '527 aenauth email')
        sendAuthorizationLink(data.id, token, data.email);
        res.send('Verification email sent.');
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Send authorization link via email
function sendAuthorizationLink(id, token, email) {
    const authorizationLink = `http://localhost:4006/verify?token=${token}&id=${id}`;
    const mailOptions = {
        from: process.env.SENT_EMAIL,
        to: email,
        subject: 'Authorization Link',
        html: `<p>Click <a href="${authorizationLink}">here</a> to authorize.</p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
}

//forget passwordlink
app.get('/forgetpasswordverify', async (req, res) => {
    const token = req.query.token;
    // const email = req.query.email;
    const id = req.query.id;

    console.log(id, '462 line from query verify')

    try {

        const tokenDoc = await adminData.findOne({ _id: id });
        console.log(tokenDoc.id, '720 line token doc')

        if (tokenDoc.id === id) {
            console.log(tokenDoc, '723 line token doc')
            await adminData.findOneAndUpdate(
                { _id: id },
                { $unset: { forgetPasswordLinkToken: 1 } },
                { new: true }
            );
            // Token is valid, mark the user as verified
            // const email = tokenDoc.value.email;
            // Perform your database operation to mark the user as verified
            // For demonstration purposes, just log the email
            console.log(`User with email ${id} is verified.`);
            // Redirect to the login page
            res.redirect('http://localhost:3009/forgetpasswordotpcheck');
        } else {
            // Token is invalid or expired
            res.send('Invalid token.');
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to initiate email verification
app.post('/forgetpasswordlink', async (req, res) => {

    const token = generateToken();
    try {
        const { email } = req.body;
        console.log(email + "from input")
        let checked;
        try {
            checked = await adminData.findOne({ email: req.body.email })
            console.log(checked + "from db")
        } catch (err) {
            console.log(err)
        }
        if (!checked) {
            return res.status(400).send('User Not Found');
        }
        try {

            // Insert token into database
            console.log("766 line req.body.emailcheck:", req.body.email);
            console.log("Email sent successfully!");
            let data = await adminData.findOneAndUpdate({ _id: checked.id }, { forgetPasswordLinkToken: token }, { new: true });
            if (!data) {
                return res.status(400).send('User Not Found');
            }
            // Send the authorization link via email
            console.log(data.email, '773 aenauth email')
            sendForgetAuthorizationLink(data.id, token, data.email);
            res.send('Verification email sent.');
        } catch (error) {
            console.error('Error:', error);
            res.status(500).send('Internal Server Error');
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Send authorization link via email
function sendForgetAuthorizationLink(id, token, email) {
    const authorizationLink = `http://localhost:4006/forgetpasswordverify?token=${token}&id=${id}`;
    const mailOptions = {
        from: process.env.SENT_EMAIL,
        to: email,
        subject: 'Forget Password Link',
        html: `<p> <a href="${authorizationLink}">Click here to Reset Password</a></p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
}

// refreshtokenstart

app.get('/refresh', jwtRefreshFile.handleRefreshToken)
function testingfun(req, res) {
    const jwtCookieValue = req.cookies.jwt;
    console.log(jwtCookieValue + "tesing cookie function")
    res.status(200).send('tesing successful');

}
//using for user profile
app.get("/getadminprofile", jwtAuthorization, async (req, res) => {
    try {
        let data = await adminData.findOne({ _id: req.user.id });
        console.log(data + "from google data")
        if (!data) {
            data = await googleAdmin.findOne({ _id: req.user.id });
            console.log("from vendor data : " + data)
            const encryptioniv = Buffer.from(data.initializationVector, 'base64');
            console.log("from vendor data : " + encryptioniv)

            const key = process.env.CRYPTO_ENCRYPTION_KEY;

            const decipherFirstName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
            const decipherLastName = crypto.createDecipheriv('aes-256-cbc', key, encryptioniv);
            let firstNameDecrypted = decipherFirstName.update(data.firstName, 'hex', 'utf8');
            firstNameDecrypted += decipherFirstName.final('utf8');
            let lastNameDecrypted = decipherLastName.update(data.lastName, 'hex', 'utf8');
            lastNameDecrypted += decipherLastName.final('utf8');
            console.log('from vendor profile : ' + firstNameDecrypted + "" + lastNameDecrypted)
            data = {
                firstName: firstNameDecrypted,
                lastName: lastNameDecrypted
            }
        }
        res.status(200).json(data);
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
});







// Add Passport.js middleware after express-session
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:4006/oauth",
    passReqToCallback: true
},
    async function (req, accessToken, refreshToken, profile, cb) {
        try {
            let existedUser;
            existedUser = await googleAdmin.findOne({ googleId: profile.id });
            if (existedUser) {
                console.log('existing');
            }
            // If the user doesn't exist, create a new user with the provided profile data
            if (!existedUser) {
                console.log('not existed and creted document');
                const userData = {
                    googleId: profile.id,
                    displayName: profile.displayName,
                    firstName: profile.name.familyName,
                    lastName: profile.name.givenName,
                    email: profile.emails[0].value,
                    image: profile.photos[0].value
                };
                existedUser = await GoogleVendorData.create(userData);
            }
            cb(null, profile);
        } catch (error) {
            // If an error occurs, pass the error to the callback function
            cb(error);
        }
    }
));

// Configure Passport.js to use session support
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});


app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/oauth', passport.authenticate('google', { failureRedirect: 'http://localhost:3009/login' }),
    async function (req, res) {
        console.log("Request path:", req.path);
        let existedUser = await GoogleVendorData.findOne({ googleId: req.user.id });
        console.log(existedUser)
        if (!existedUser) {
            return res.status(404).json({ message: 'google user not found' });
        }
        const userData = {
            user: {
                id: existedUser._id
            }
            // Other user data as needed
        };
        // Generate JWT token or session data
        const token = jwt.sign(userData, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE });
        console.log("token :", token)
        // Send the token in the Authorization header
        res.set('Authorization', `Bearer ${token}`);
        // Respond with a redirection
        res.redirect(`http://localhost:3009/login?token=${token}`);
    });




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

