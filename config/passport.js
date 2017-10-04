var passport = require('passport');
var FacebookStrategy = require('passport-facebook').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var mongoose = require('mongoose');
var User = mongoose.model('User');
var configAuth = require('./oath.js');

passport.use(new LocalStrategy({
    usernameField: 'user[email]',
    passwordField: 'user[password]'
}, function(email, password, done) {
    User.findOne({email: email}).then(function(user){
        if(!user || !user.validPassword(password)){
            return done(null, false, {errors: {'email or password': 'is invalid'}});
        }

        return done(null, user);
    }).catch(done);
}));

passport.use(new FacebookStrategy({
    clientID: configAuth.facebookAuth.ClientID,
    clientSecret: configAuth.facebookAuth.clientSecret,
    callbackURL: configAuth.facebookAuth.callbackURL,
    enableProof: true
}, function(accessToken, refreshToken, profile, cb){
        User.findOrCreate({facebookId: profile.id}, function (err, user) {
            return cb(err, user);
        });
}
));