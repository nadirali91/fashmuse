var mongoose = require('mongoose');
var uniqueValidator = require('mongoose-unique-validator');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var secret = require('../config').secret;


var UserSchema = new mongoose.Schema({
  firstname: {type: String, lowercase: true, match: [/^[a-zA-Z0-9]+$/, 'is invalid']},
  lastname: {type: String, lowercase: true, match: [/^[a-zA-Z0-9]+$/, 'is invalid']},
  gender: {type: String, lowercase: true, match: [/^[a-zA-Z0-9]+$/, 'is invalid']},
  birthdate: Date,
  username: {type: String, unique: true, lowercase: true, required: [true, "can't be blank"], match: [/^[a-zA-Z0-9]+$/, 'is invalid'], index: true},
  email: {type: String, unique: true, lowercase: true, required: [true, "can't be blank"], match: [/\S+@\S+\.\S+/, 'is invalid'], index: true},
  bio: String,
  image: String,
  hash: String,
  salt: String
}, {timestamps: true});

UserSchema.methods.setPassword = function(password){
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 512, 'sha512').toString('hex');
};

UserSchema.methods.validPassword = function(password){
    var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 512, 'sha512').toString('hex');
    return this.hash === hash;
};

UserSchema.methods.generateJWT = function() {
    var today = new Date();
    var exp = new Date(today);
    exp.setDate(today.getDate() + 45);

    return jwt.sign({
        id: this._id,
        username: this.username,
        exp: parseInt(exp.getTime() / 1000),
        }, secret);
};

UserSchema.methods.toAuthJson = function(){
    return {
        firstname: this.firstname,
        lastname: this.lastname,
        gender: this.gender,
        birthdate: this.birthdate,
        username: this.username,
        email: this.email,
        token: this.generateJWT(),
        bio: this.bio,
        image: this.image
    };
};

mongoose.model('User', UserSchema);