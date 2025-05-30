var express = require('express');
var router = express.Router();

router.get('/', function(req, res, next) {
  res.send('v1 API');
});

module.exports = router;
