const express = require('express')
const uploadImage = require('../../helper/imagehandler') // Image handle Area
const authcontroller = require('../../controller/authcontroller/authcontroller')
const { Auth } = require('../../middleware/auth')
const router = express.Router()

router.post('/register', uploadImage.single('image'), authcontroller.register)
router.post('/login', authcontroller.login)
router.get('/dashboard', Auth, authcontroller.dashboard)

module.exports = router