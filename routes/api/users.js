var mongoose = require('mongoose');
var router = require('express').Router();
var passport = require('passport');
var User = mongoose.model('User');
var auth = require('../auth');

router.post('/users', function(req, res, next) {
    var user = new User();

    user.firstname = req.body.user.firstname;
    user.lastname = req.body.user.lastname;
    user.username = req.body.user.username;
    user.email = req.body.user.email;
    user.setPassword(req.body.user.password);

    user.save().then(function(){
        return res.json({user: user.toAuthJSON()});
    }).catch(next);
});

router.use(function(err, req, res, next){
    if(err.name === 'ValidationError'){
        return res.status(422).json({
            errors: Object.keys(err.errors).reduce(function(errors, key){
                errors[key] = err.errors[key].message;

                return errors;
            }, {})
        });
    }

    return next(err);
});

router.post('/users/login', function(req, res, next){
    if(!req.body.user.email){
        return res.status(422).json({errors: {email: "can't be blank"}});
    }

    if(!req.body.user.password){
        return res.status(422).json({errors: {password: "can't be blank"}});
    }

    passport.authenticate('local', {session: false}, function(err, user, info){
        if(err){ return next(err); }

        if(user){
            user.token = user.generateJWT();
            return res.json({user: user.toAuthJSON()});
        } else {
            return res.status(422).json(info);
        }
    })(req, res, next);
});

// facebook authentication route

router.get('/auth/facebook', passport.authenticate('facebook'));

router.get('/auth/facebook/callback', passport.authenticate('facebook', {failureRedirect: '/login'}),
    function(req, res) {
        res.redirect('/');
    });

router.get('/user', auth.required, function(req, res, next){
    user.findById(req.payload.id).then(function(user){
        if(!user){ return res.sendStatus(401); }

        return res.json({user: user.toAuthJSON()});
    }).catch(next);
});

router.put('/user', auth.required, function(req, res, next){
    User.findById(req.payload.id).then(function(user){
        if(!user){ return res.sendStatus(401); }

        if(typeof req.body.user.firstname !== 'undefined'){
            user.firstname = req.body.user.firstname;
        }
        if(typeof req.body.user.lastname !== 'undefined'){
            user.lastname = req.body.user.lastname;
        }
        if(typeof req.body.user.gender !== 'undefined'){
            user.gender = req.body.user.gender;
        }
        if(typeof req.body.user.birthdate !== 'undefined'){
            user.birthdate = req.body.user.birthdate;
        }
        if(typeof req.body.user.username !== 'undefined'){
            user.username = req.body.user.username;
        }
        if(typeof req.body.user.email !== 'undefined'){
            user.email = req.body.user.email
        }
        if(typeof req.body.user.bio !== 'undefined'){
            user.bio = req.body.user.bio;
        }
        if(typeof req.body.user.image !== 'undefined'){
            user.image = req.body.user.image;
        }
        if(typeof req.body.user.password !== 'undefined'){
            user.setPassword(req.body.user.password);
        }

        return user.save().then(function(){
            return res.json({user: user.toAuthJSON()});
        });
    }).catch(next);
});

module.exports = router;