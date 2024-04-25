const express = require('express');
const router = express.Router();
const jwtAuthorization = require('../jwtmiddleware');

const analyticsController = require('../controllers/analyticsController');



router.post('/search', analyticsController.search);
router.get('/getsearchcount', analyticsController.getsearchcount);
router.get('/analytics/popular-searches', analyticsController.popularSearches);
router.post('/click', analyticsController.click);
router.get('/getclickcount', analyticsController.getclickcount);
router.get('/analytics/popular-clicks', analyticsController.popularClicks);
router.post('/analytics/vendor/popular-clicks', analyticsController.vendorPopularClicks);
router.post('/view', analyticsController.view);
router.get('/getviewcount', analyticsController.getviewcount);
router.get('/analytics/popular-views', analyticsController.popularViews);
router.post('/analytics/vendor/popular-views', analyticsController.vendorPopularViews);
router.get('/analytics/popular-categories', analyticsController.popularCategories);
router.post('/sendsessionduration', analyticsController.sendsessionduration);
router.get('/analytics/average-session-duration', analyticsController.getAvgSessionDuration);
router.get('/activeuserscount', analyticsController.activeuserscount);



module.exports = router;