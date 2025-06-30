const express = require('express');
const { body } = require('express-validator');
const User = require('../models/user');

const router = express.Router();
const authController = require('../controllers/auth');

router.get('/login', authController.getLogin);
router.post('/login', 
    [
        body(
            'email', 
            'Please enter a valid email.'
        )
        .isEmail()
        .normalizeEmail(),
        body('password')
        .isLength({min: 8, max: 16})
        .withMessage('Password must be between 8 and 16 characters long.')
        .trim()
    ],
    authController.postLogin);
router.post('/logout', authController.postLogout);
router.get('/signup', authController.getSignup);
router.post('/signup', 
    [
        body(
            'email', 
            'Please enter a valid email.'
        )
        .isEmail()
        .custom((value, { req }) => {
            return User.findByEmail(value)
            .then(user => {
                if (user) {
                    return Promise.reject('E-Mail exists already, please pick a different one!');
                }
            })
        })
        .normalizeEmail(),
        body('password')
        .isLength({min: 8, max: 16})
        .withMessage('Password must be between 8 and 16 characters long.')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d\s])[^\s]{8,16}$/)
        .withMessage('Password must include at least one lowercase letter, one uppercase letter, one number, one special character, and no spaces.')
        .trim(),
        body('confirmPassword')
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Passwords have to match!');
            }
            return true;
        })
        .trim()
    ],
    authController.postSignup
);
router.get('/reset', authController.getReset);
router.post('/reset', authController.postReset);
router.get('/reset/:token', authController.getNewPassword);
router.post('/new-password', authController.postNewPassword);

module.exports = router;