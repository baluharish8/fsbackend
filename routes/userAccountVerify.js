const express = require('express');
const router = express.Router();
const jwtAuthorization = require('../jwtmiddleware');

const usrerAccountVerifyController = require('../controllers/usrerAccountVerifyController');

router.post('/sendverification',jwtAuthorization , usrerAccountVerifyController.sendverification);
router.get('/verify', usrerAccountVerifyController.verify);




module.exports = router;