const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const User = require('../../models/User');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

// @route     POST api/users
// @desc      Register User
// @access    Public
router.post(
  '/',
  [
    check('name', 'Name is required')
      .not()
      .isEmpty(),
    check('email', 'Enter valid email').isEmail(),
    check(
      'password',
      'Enter valid password with more than 5 characters',
    ).isLength({ min: 5 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password } = req.body;
    try {
      // see if user exists
      let user = await User.findOne({ email });
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'user already exists' }] });
      }
      // get users gravtar
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm',
      });

      user = new User({
        name,
        email,
        avatar,
        password,
      });

      // encrypt password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

      await user.save();

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
