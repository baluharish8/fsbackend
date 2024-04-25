// userRoutes.js

const express = require('express');
const router = express.Router();
const jwtAuthorization = require('../jwtmiddleware');

const authUserController = require('../controllers/authUserController');

// Define routes and link them to controller functions
router.post('/registration1', authUserController.registration1);
router.post('/login', authUserController.login);
router.post('/otpverify',jwtAuthorization , authUserController.otpverify);
//resend otp to gmail
router.post('/otpsend',jwtAuthorization , authUserController.otpsend);
//resend otp to mobile
router.post('/mobileotpsend',jwtAuthorization , authUserController.mobileotpsend);
//vendor login
router.post('/vendorlogin' , authUserController.vendorlogin);




module.exports = router;
