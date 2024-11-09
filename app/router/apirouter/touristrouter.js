const express = require('express')
const touristcontroller = require('../../controller/apicontroller/touristcontroller')
const uploadImage = require('../../helper/imagehandler') // Image handle Area
const router = express.Router()

router.post('/createtourist', uploadImage.single('image'), touristcontroller.create)
router.get('/touristlist', touristcontroller.getall)
router.get('/touristlist/:id', touristcontroller.getsingle)
router.put('/updatetourist/:id', uploadImage.single('image'), touristcontroller.touristupdate)
router.delete('/deletetourist/:id', touristcontroller.touristdelete)

module.exports = router