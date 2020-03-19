const express = require('express');
const router = express.Router();
const passport = require('passport');
const userFunction = require('../services/userFunctions');
const User = require('../models/user');
const passportStrategy = require('passport-local').Strategy;
const bcrypt = require("bcrypt");
const async = require('async');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const auth = require('../middleware/authentication');
const multer = require('multer');
const cloudinary = require('cloudinary');
const cloudinaryStorage = require('multer-storage-cloudinary');
salt_factor = 8;


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
                    user.lastLogin.push(Date(Date.now()).toString());
                    user.save();
                    return done(null, user);
                })
                .catch(err => done(err));
        });
    })
);


cloudinary.config({
    cloud_name: 'inkers123',
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = cloudinaryStorage({
    cloudinary: cloudinary,
    allowedFormats: ["jpg", "png"], 
});

const upload = multer({
    storage: storage,
    // fileFilter: fileFilter
});


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
    })
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

router.get('/logout', (req, res) => {
    req.logout();
    res.redirect("/login");
});

router.get('/user', auth.isLoggedIn , (req, res) => {
    res.render('user');
});

router.get('/forgot', (req, res) => {
    res.render('forget');
});

router.post('/forgot', function (req, res, next) {
    async.waterfall([
        function (done) {
            crypto.randomBytes(20, function (err, buf) {
                var token = buf.toString('hex');
                done(err, token);
            });
        },
        function (token, done) {
            User.findOne({ email: req.body.email }, function (err, user) {
                if (!user) {
                    //req.flash('error', 'No account with that email address exists.');
                    return res.redirect('/forgot');
                }

                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                user.save(function (err) {
                    done(err, token, user);
                });
            });
        },
        function (token, user, done) {
            var smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: 'ntndhiman1712@gmail.com',
                    pass: process.env.GMAILPW
                }
            });
            var mailOptions = {
                to: user.email,
                from: 'ntndhiman1712@gmail.com',
                subject: 'Inkers Password Reset',
                text: 'You are receiving this because you have requested the reset of the password for your Inkers account.\n\n' +
                    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                    'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                    'If you did not request this, please ignore this email and your password will remain unchanged.\n'
            };
            smtpTransport.sendMail(mailOptions, function (err) {
                console.log('mail sent');
                //req.flash('success', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
                done(err, 'done');
            });
        }
    ], function (err) {
        if (err) return next(err);
        res.redirect('/forgot');
    });
});

router.get('/reset/:token', function (req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function (err, user) {
        if (!user) {
            //req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }
        res.render('reset', { token: req.params.token });
    });
});

router.post('/reset/:token', function (req, res) {
    async.waterfall([
        function (done) {
            User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function (err, user) {
                if (!user) {
                    //req.flash('error', 'Password reset token is invalid or has expired.');
                    return res.redirect('back');
                }
                if (req.body.password === req.body.confirm) {
                    console.log(user);
                    console.log(user.password);
                    user.password = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(salt_factor), null);
                    user.resetPasswordToken = undefined;
                    user.resetPasswordExpires = undefined;
                    user.save().then(err => req.logIn(user, (err) => { done(err, user) }));
                } else {
                    //req.flash("error", "Passwords do not match.");
                    return res.redirect('back');
                }
            });
        },
        function (user, done) {
            var smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: 'ntndhiman1712@gmail.com',
                    pass: process.env.GMAILPW
                }
            });
            var mailOptions = {
                to: user.email,
                from: 'ntndhiman1712@gmail.com',
                subject: 'Your password has been changed',
                text: 'Hello,\n\n' +
                    'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
            };
            smtpTransport.sendMail(mailOptions, function (err) {
                //req.flash('success', 'Success! Your password has been changed.');
                done(err);
            });
        }
    ], function (err) {
        res.redirect('/');
    });
});

/// after user logged in;

router.get("/user/profile", auth.isLoggedIn, (req, res, next) => {
    res.render("profile");
});

router.get("/user/updatePass", auth.isLoggedIn, (Req, res, next) => {
    res.render('updatePass');
});

router.post("/user/updatePass", auth.isLoggedIn, async (req, res, next) => {
    await User.find({
        _id: req.user._id
    })
    .exec()
    .then(user => {
        if(!user) console.log('not a user');
        console.log(user);
        user[0].password = bcrypt.hashSync(req.body.updatePass, bcrypt.genSaltSync(salt_factor), null);
        user[0].save().then(user => console.log("updated successfully"));
        res.redirect('/user/profile');
    }).catch(err => {
        console.log(err);
        next(err);
    });
});

router.post('/user/upload', upload.single('image'), async (req, res, next) => {
    await User.find({
        _id: req.user._id
    })
    .exec()
    .then(user => {
        console.log(user);
        user[0].image.push(req.file);
        user[0].save().then(user => {console.log('photo uploaded')});
        console.log(user);
        res.redirect('/user');
    })
    .catch(err => {
        console.log(err);
        next(err);
    })
});

// router.post('/user/delete', async (req, res, next) => {
//     await User.find({
//         _id: req.user._id
//     })
//     .exec()
//     .then(user => {
//         console.log(user[0].images.public_id);
//         cloudinary.uploader.destroy(user[0].image.public_id, () => {
//             console.log('post deleted from cloudinary');
//         });
//         user[0].image.pop(user[0].image.public_id);
//         res.redirect('/user');

//     })
//     .catch(err => {
//         console.log(err);
//         next(err);
//     })
// })

module.exports = router;