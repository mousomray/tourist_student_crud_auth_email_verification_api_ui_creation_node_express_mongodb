const express = require('express');
const uiauthcontroller = require('../../controller/uiauthcontroller/uiauthcontroller');
const { uiAuth } = require('../../middleware/uiauth'); // For UI auth
const uploadImage = require('../../helper/imagehandler') // Image handle Area
const router = express.Router();

router.get('/register', uiauthcontroller.register) // Show Register Form
router.post('/registercreate', uploadImage.single('image'), uiauthcontroller.register);
router.get('/login', uiauthcontroller.login) // Get data in login
router.post('/logincreate', uiauthcontroller.login) // Post data in login
router.get('/logout', uiauthcontroller.logout); // For Logout
router.get('/dashboard', uiAuth, uiauthcontroller.dashboardpage); // For Dashboard
router.get('/forgetpassword', uiauthcontroller.forgotpassword); // Show Forget Form
router.post('/forgetpasswordcreate', uiauthcontroller.forgotpassword); // Post data in Forget
router.get('/updatepassword',uiAuth, uiauthcontroller.updatepassword); // Show Update Form 
router.post('/updatepasswordcreate', uiAuth, uiauthcontroller.updatepassword); // Post Update
router.get('/deleteuser', uiAuth, uiauthcontroller.deleteUser); // Show delete user form 
router.post('/deleteusercreate', uiAuth, uiauthcontroller.deleteUser); // Post delete user

module.exports = router; 