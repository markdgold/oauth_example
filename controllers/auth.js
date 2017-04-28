//Requires and Globals
var express = require('express');
var passport = require('../config/passportConfig');
var db = require('../models');
var router = express.Router();

//Routes
router.get('/login', function(req, res) {
    res.render('loginForm');
});

router.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    successFlash: 'Good job, you logged in.',
    failureRedirect: '/auth/login',
    failureFlash: 'Try again, loser.'
}));

router.get('/signup', function(req, res) {
    res.render('signupForm');
});

router.post('/signup', function(req, res, next) {
    db.user.findOrCreate({
        where: { email: req.body.email },
        defaults: {
            'firstName': req.body.firstName,
            'lastName': req.body.lastName,
            'password': req.body.password
        }
    }).spread(function(user, wasCreated) {
        if (wasCreated) {
            //good
            passport.authenticate('local', {
                successRedirect: '/profile',
                successFlash: 'Good job, you signed up',
                failureRedirect: '/auth/login',
                failureFlash: 'Unknown error. Please log in.'
            })(req, res, next);
        } else {
            //bad
            req.flash('error', 'Email already exists. Please log in.');
            res.redirect('/auth/login');
        }
    }).catch(function(error) {
        req.flash('error', error.message);
        res.redirect('/auth/signup');
    });
});

router.get('/logout', function(req, res) {
    req.logout();
    req.flash('success', 'You logged out');
    res.redirect('/');
});

//facebook auth section
router.get('/facebook', passport.authenticate('facebook', {
    scope: ['public_profile', 'email']
}));

router.get('/callback/facebook', passport.authenticate('facebook', {
    successRedirect: '/profile',
    successFlash: 'You have logged in with Facebork.',
    failureRedirect: '/auth/login',
    failureFlash: 'Invalid Login'
}));

//Export
module.exports = router;
