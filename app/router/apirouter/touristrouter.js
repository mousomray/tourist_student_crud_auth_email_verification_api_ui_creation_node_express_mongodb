const express = require('express')
const touristcontroller = require('../../controller/apicontroller/touristcontroller')
const uploadImage = require('../../helper/imagehandler') // Image handle Area
const { Auth } = require('../../middleware/auth')
const router = express.Router()

router.post('/createtourist', Auth, uploadImage.single('image'), touristcontroller.create)
router.get('/touristlist', Auth, touristcontroller.getall)
router.get('/touristlist/:id', Auth, touristcontroller.getsingle)
router.put('/updatetourist/:id', Auth, uploadImage.single('image'), touristcontroller.touristupdate)
router.delete('/deletetourist/:id', Auth, touristcontroller.touristdelete)

module.exports = router