const adminData = require('../models/admindata')
const googleAdmin = require('../models/googleadmin')
const VendorData = require('../models/mvmodels')
const ServiceData = require('../models/vendorservicesdata')
const crypto = require("crypto"); // for data encryption
const bcrypt = require('bcryptjs'); // for password hashing
const nodemailer = require("nodemailer");
const jwt = require('jsonwebtoken');

// Route to initiate email verification
// Generate a random token
function generateToken() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}
let transporter = nodemailer.createTransport({
    service: process.env.SENT_HOST,
    auth: {
        user: process.env.SENT_EMAIL,
        pass: process.env.SENT_PASSWORD
    }
});


const sendverification = async (req, res) => {

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
}

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


// app.get('/verify', async (req, res) => {
const verify = async (req, res) => {
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
}

module.exports = {
    sendverification,
    verify,
};