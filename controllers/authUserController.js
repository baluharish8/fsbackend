const adminData = require('../models/admindata')
const googleAdmin = require('../models/googleadmin')
const VendorData = require('../models/mvmodels')
const ServiceData = require('../models/vendorservicesdata')
const crypto = require("crypto"); // for data encryption
const bcrypt = require('bcryptjs'); // for password hashing
const nodemailer = require("nodemailer");
const jwt = require('jsonwebtoken');
const { Vonage } = require('@vonage/server-sdk')

// app.post("/registration1", async (req, res) => {
const registration1= async (req, res) => {

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
}



  function generateOTP() {

    const digitChars = '0123456789';

    const otp = Math.floor(100000 + Math.random() * 900000);
    console.log('Generated OTP:', otp);
    return otp
}
const login= async (req, res) => {
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
}

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

//otp Verification
    const otpverify = async (req, res) => {
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
}
//resend otp to gmail
let transporter = nodemailer.createTransport({
    service: process.env.SENT_HOST,
    auth: {
        user: process.env.SENT_EMAIL,
        pass: process.env.SENT_PASSWORD
    }
});
    const otpsend = async (req, res) => {

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
}
//resend otp to mobile

    const mobileotpsend = async (req, res) => {

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
}

//vendor login
    const vendorlogin = async (req, res) => {
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

            // Retrieve encryptionivBase64 from the database
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
   
        )

        const refreshToken = jwt.sign(payload, 'refreshVendorSecretKey', { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });

        try {

            const updatedVendorData = await VendorData.findOneAndUpdate({ email: req.body.email }, { refreshToken: refreshToken }, { new: true });

            console.log(updatedVendorData + "dbtokencraeteResponse")

      

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
}

module.exports = {
    registration1,
    login,
    otpverify,
    otpsend,
    mobileotpsend,
    vendorlogin,
  };