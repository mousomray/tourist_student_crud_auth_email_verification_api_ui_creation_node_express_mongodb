const express = require('express');
const homecontroller = require('../../controller/uiapicontroller/homeuicontroller');
const { uiAuth } = require('../../middleware/uiauth'); // For UI auth
const router = express.Router();

router.get('/', uiAuth, homecontroller.home);

module.exports = router; 