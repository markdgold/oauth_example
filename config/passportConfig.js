var passport = require('passport');
var localStrategy = require('passport-local').Strategy;
var facebookStrategy = require('passport-facebook').Strategy;
var db = require('../models');

passport.serializeUser(function(user, cb) {
    cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
    db.user.findById(id).then(function(user) {
        cb(null, user);
    }).catch(cb);
});

passport.use(new localStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, function(email, password, cb) {
    db.user.findOne({
        where: { email: email }
    }).then(function(user) {
        if (!user || !user.isValidPassword(password)) {
            cb(null, false); //No user or bad password
        } else {
            cb(null, user); //User is allowed
        }
    }).catch(cb);
}));

passport.use(new facebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: process.env.BASE_URL + '/auth/callback/facebook',
    profileFields: ['id', 'email', 'displayName'],
    enabledProof: true
}, function(accessToken, refreshToken, profile, cb) {
    //see if we can get the email from facebook profile
    var email = profile.emails ? profile.emails[0].value : null;

    //see if the user already exists in the database
    db.user.findOne({
        where: { email: email }
    }).then(function(existingUser) {
        //this person has logged in before
        if (existingUser && email) {
            existingUser.updateAttributes({
                facebookId: profile.id,
                facebookToken: accessToken
            }).then(function(updatedUser) {
                cb(null, updatedUser);
            }).catch(cb);
        } else {
            //New person in db but logged in w/fb
            db.user.findOrCreate({
                where: { facebookId: profile.id },
                defaults: {
                    facebookToken: accessToken,
                    email: email,
                    firstName: profile.displayName.split(' ')[0],
                    lastName: profile.displayName.split(' ')[1]
                }
            }).spread(function(user, wasCreated) {
                if (wasCreated) {
                    //they were new, so created account
                    cb(null, user);
                } else {
                    //not new afterall, update token
                    user.facebookToken = accessToken;
                    user.save().then(function() {
                        cb(null, user);
                    }).catch(db);

                }
            }).catch(db);
        }
    });
}));


module.exports = passport;
