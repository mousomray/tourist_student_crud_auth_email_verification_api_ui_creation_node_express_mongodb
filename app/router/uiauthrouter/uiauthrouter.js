const express = require('express');
const uiauthcontroller = require('../../controller/uiauthcontroller/uiauthcontroller');
const { uiAuth } = require('../../middleware/uiauth'); // For UI auth
const uploadImage = require('../../helper/imagehandler') // Image handle Area
const router = express.Router();

router.get('/register', uiauthcontroller.registerGet) // Show Register Form
router.post('/registercreate', uploadImage.single('image'), uiauthcontroller.registerPost);
router.get('/verifyuser', uiauthcontroller.verifyOtpGet) // For to show verify user form 
router.post('/verifyusercreate', uiauthcontroller.verifyOtpPost) // For to add data verify user form 
router.get('/login', uiauthcontroller.loginGet) // Get data in login
router.post('/logincreate', uiauthcontroller.loginPost) // Post data in login
router.get('/logout', uiauthcontroller.logout); // For Logout
router.get('/dashboard', uiAuth, uiauthcontroller.dashboardpage); // For Dashboard
router.get('/updatepassword', uiAuth, uiauthcontroller.updatepasswordGet); // Show Update Form 
router.post('/updatepasswordcreate', uiAuth, uiauthcontroller.updatepasswordPost); // Post Update
router.get('/passwordresetlink', uiauthcontroller.resetpasswordlinkGet);// Show reset link from
router.post('/passwordresetlinkcreate', uiauthcontroller.resetpasswordlinkPost);// Show Data 
router.get('/forgetpassword/:id/:token', uiauthcontroller.forgetPasswordGet) // Show Forget Form
router.post('/forgetpasswordcreate/:id/:token', uiauthcontroller.forgetPasswordPost) //Add data
router.get('/deleteuser', uiAuth, uiauthcontroller.deleteUserGet); // Show delete user form 
router.post('/deleteusercreate', uiAuth, uiauthcontroller.deleteUserPost); // Post delete user

module.exports = router;  