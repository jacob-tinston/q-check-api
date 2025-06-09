const express = require('express');
const validator = require('validator');
const { probeDomain } = require('../../utils/domain');
const router = express.Router();

router.get('/scan', async (req, res, next) => {
  const domain = req.query.domain?.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');

  if (!domain) {
    next(new Error('Missing query parameter: domain'));
  } else if (!validator.isFQDN(domain)) {
    next(new Error('Invalid domain format'));
  }

  try {
    const data = await probeDomain(domain);

    // TODO: Scoring logic
    
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
