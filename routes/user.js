const express = require('express');
const router = express.Router();
const passport = require('passport');
const userFunction = require('../services/userFunctions');
const User = require('../models/user');
const passportStrategy = require('passport-local').Strategy;
const bcrypt = require("bcrypt");
// const request = require('request-promise');
const mongoose = require('mongoose');

passport.serializeUser((user, done) => done(null, user.id));

    passport.deserializeUser((id, done) => {
        User.findById(id)
            .exec()
            .then(user => done(null, user))
            .catch(err => done(err));
    });

passport.use(
    new passportStrategy({
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true
    }, (req, email, password, done) => {
        process.nextTick(() => {
            User.findOne({
                email: email
            }).exec()
                .then(user => {
                    if (!user) {
                        console.log("wrong id");
                        return done(null, false);
                    }
                    if (!bcrypt.compareSync(password, user.password)) {
                        console.log("wrong password");
                        return done(null, false);
                    }
                    console.log("password correct, success");
                    return done(null, user);
                })
                .catch(err => done(err));
        });
    })
);


router.get('/', (req, res) => {
    res.redirect('login');
});

router.get('/login', (req, res) => {
    res.render('login');
});

router.post("/login",
    passport.authenticate("local", {
        successRedirect: "/user",
        failureRedirect: "/login"
    }), (req, res, next)=>{
    }
);

router.get('/register', (req, res) => {
    res.render('register');
});

router.post('/register', async (req, res, next) => {
    return userFunction.addUser(req.body)
        .then(message => {
            if (message === 'ok')
                return res.redirect('/login');
        })
        .catch(err => {
            console.log(err);
            next(err);
        })
});

router.post('/logout', (req, res) => {
    req.logout();
    res.redirect("/login");
});

router.get('/user', (req, res) => {
    res.render('user');
});

module.exports = router;