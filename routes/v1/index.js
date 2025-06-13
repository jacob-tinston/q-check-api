const express = require('express');
const { validateDomain, probeDomain } = require('../../utils/domain');
const { scoreQuantumResistance } = require('../../utils/score');
const router = express.Router();

router.get('/scan', async (req, res, next) => {
  if (!req.query.domain) {
    return res.status(400).json({ success: false, error: 'Missing query parameter: domain' });
  }

  const domain = validateDomain(req.query.domain);

  if (!domain) {
    return res.status(400).json({ success: false, error: 'Invalid domain format' });
  }

  try {
    const probeData = await probeDomain(domain);
    const scoreData = scoreQuantumResistance(probeData);
  
    return res.status(200).json({ 
      success: true, 
      probe: {
        domain,
        data: probeData
      },
      score: scoreData
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err });
  }
});

module.exports = router;
