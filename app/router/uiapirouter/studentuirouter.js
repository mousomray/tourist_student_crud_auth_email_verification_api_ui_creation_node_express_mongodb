const express = require('express');
const studentuicontroller = require('../../controller/uiapicontroller/studentuicontroller');
const { uiAuth } = require('../../middleware/uiauth'); // For UI auth
const router = express.Router();

router.get('/addstudent', uiAuth, studentuicontroller.addstudent);
router.post('/addstudentcreate', uiAuth, studentuicontroller.addstudent);
router.get('/studentlist', uiAuth, studentuicontroller.getall);
router.get('/singlestudent/:id', uiAuth, studentuicontroller.singlestudent);
router.post('/updatestudent/:id', uiAuth, studentuicontroller.updatestudent);
router.get('/deletestudent/:id', uiAuth, studentuicontroller.deleteestudent);

module.exports = router; 