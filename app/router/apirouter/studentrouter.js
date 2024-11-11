const express = require('express')
const studentcontroller = require('../../controller/apicontroller/studentcontroller')
const { Auth } = require('../../middleware/auth')
const router = express.Router()

router.post('/addstudent', Auth, studentcontroller.create)
router.get('/getstudent', Auth, studentcontroller.getall)
router.get('/getstudent/:id', Auth, studentcontroller.getsingle)
router.put('/updatestudent/:id', Auth, studentcontroller.studentupdate)
router.delete('/deletestudent/:id', Auth, studentcontroller.studentdelete)

module.exports = router