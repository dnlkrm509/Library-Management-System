const crypto = require('crypto');

const { validationResult } = require('express-validator');

const User = require('../models/user');

const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const Resend = require('resend').Resend;

dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);

exports.getLogin = (req, res, next) => {
    let message = req.flash('error');
    if (message.length > 0) {
        message = message[0];
    } else {
        message = null;
    }

    res.render('auth/login', {
        pageTitle: 'Login',
        path: '/login',
        errorMessage: message,
        oldInput: {
            email: '',
            password: ''
        },
        validationErrors: []
    })
};

exports.getSignup = (req, res, next) => {
    let message = req.flash('error');
    if (message.length > 0) {
        message = message[0];
    } else {
        message = null;
    }

    res.render('auth/signup', {
        pageTitle: 'Signup',
        path: '/signup',
        errorMessage: message,
        oldInput: {
            email: '',
            password: '',
            confirmPassword: ''
        },
        validationErrors: []
    })
};

exports.postLogin = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            pageTitle: 'Login',
            path: '/login',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email,
                password
            },
            validationErrors: errors.array()
        });
    }
    
    User.findByEmail(email)
    .then(user => {
        if (!user) {
            return res.status(422).render('auth/login', {
                pageTitle: 'Login',
                path: '/login',
                errorMessage: 'Invalid email.',
                oldInput: {
                    email,
                    password
                },
                validationErrors: [{ path: 'email' }]
            });
        }

        bcrypt
        .compare(password, user.password)
        .then(doMatch => {
            if (doMatch) {
                req.session.isLoggedIn = true;
                req.session.user = user;
                return req.session.save(err => {
                    console.log(err);
                    return res.redirect('/');
                })
            }

            return res.status(422).render('auth/login', {
                pageTitle: 'Login',
                path: '/login',
                errorMessage: 'Invalid password.',
                oldInput: {
                    email,
                    password
                },
                validationErrors: [{ path: 'password' }]
            });
        })
        .catch(err => console.log(err))
    })
    .catch(err => console.log(err))
};

exports.postSignup = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).render('auth/signup', {
            pageTitle: 'Signup',
            path: '/signup',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email,
                password,
                confirmPassword: req.body.confirmPassword
            },
            validationErrors: errors.array()
        });
    }

    bcrypt
    .hash(password, 12)
    .then(hashedPassword => {
        const user = new User(email, hashedPassword, { resources: [] });

        return user.save();
    })
    .then(result => {
        res.redirect('/login');
        return resend.emails.send({
            to: [ email ],
            from: 'Strong Library <onboarding@resend.dev>',
            subject: 'Welcome to our Library members',
            html: '<h1>Hello</h1><p>You successfully signed up!</p>'
        });
    })
    .catch(err => console.log(err))
};

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err);
        res.redirect('/');
    })
};

exports.getReset = (req, res, next) => {
    let message = req.flash('error');
    if (message.length > 0) {
        message = message[0];
    } else {
        message = null;
    }

    res.render('auth/reset', {
        pageTitle: 'Reset Password',
        path: '/reset',
        errorMessage: message
    })
};

exports.postReset = (req, res, next) => {
    const email = req.body.email;
    crypto.randomBytes(32, (err, buffer) => {
        if(err) {
            return res.redirect('/reset');
        }
        const token = buffer.toString('hex');
        User.findByEmail(email)
        .then(user => {
            if (!user) {
                req.flash('error', 'No account with that email found.');
                return res.redirect('/reset');
            }
        
            const newUser = new User(user.email, user.password, user.borrowedItems, user._id.toString(), token, Date.now() + 3600000);
            return newUser.save()
        })
        .then(result => {
        res.redirect('/');
        resend.emails.send({
            to: [ email ],
            from: 'Strong Library <onboarding@resend.dev>',
            subject: 'Password Reset',
            html: `
                <p>You requested password reset</p>
                <p>Click this <a href="http://localhost:8080/reset/${token}">link</a> to set a new password.</p>
            `
            });
        })
        .catch(err => console.log(err));
    })
};

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token;

    User.findByPasswordToken(token)
    .then(user => {
        if (!user) {
            req.flash('error', 'No account found.');
            return res.redirect('/reset');
        }
        let message = req.flash('error');
        if (message.length > 0) {
            message = message[0];
        } else {
            message = null;
        }
        console.log(token)
        res.render('auth/new-password', {
            path: '/new-password',
            pageTitle: 'New Password',
            errorMessage: message,
            token: token,
            userId: user._id.toString()
        });
    })
    .catch(err => console.log(err));
};

exports.postNewPassword = (req, res, next) => {
    const userId = req.body.userId;
    const token = req.body.token;
    const password = req.body.password;

    let resetUser;

    User.findByUserIdANDToken(userId, token)
    .then(user => {
        resetUser = user;
        return bcrypt.hash(password, 12);
    })
    .then(hashedPassword => {
        const newUser = new User(
            resetUser.email, hashedPassword, resetUser.borrowedItems,
            resetUser._id.toString(), undefined, undefined
        )
        return newUser.save();
    })
    .then(result => {
        res.redirect('/login');
        resend.emails.send({
            to: [ resetUser.email ],
            from: 'Strong Library <onboarding@resend.dev>',
            subject: 'Password Reset',
            html: `
                <p>Your password changed.</p>
            `
        });
    })
    .catch(err => console.log(err));
};