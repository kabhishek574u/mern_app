const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');

const { check, validationResult } = require('express-validator');
// const User = require('../../models/User');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

// @route     GET api/auth
// @desc      Test route
// @access    Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
  }

  // res.send('Auth Route');
});

// @route     POST api/auth
// @desc      Authenticate User and get token
// @access    Public
router.post(
  '/',
  [
    check('email', 'Enter valid email').isEmail(),
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    try {
      // see if user exists
      let user = await User.findOne({ email });
      console.log("user*****----->", user)
      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'invalid credentials --- 1' }] });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'invalid credentials --- 2' }] });
      }
      // return jsonwebtoken
      const payload = {
        user: { id: user.id },
      };
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {
          expiresIn: 36000000,
        },
        (err, token) => {
          // console.log("err, token ****", err, token)
          if (err) throw err;
          res.json({ token });
        },
      );
      // console.log('req.body **', req.body);
      // res.send('User Registered!');
    } catch (err) {
      console.error(err.message);
      res.status(500).send('server error');
    }
  },
);

module.exports = router;
