
const createError = require('http-errors');
const express = require('express');
const app = express();
const logger = require('morgan');
const bodyParser = require('body-parser');
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('cookie-session');
const mongoose = require('mongoose');
const passport = require('passport');
const localStrategy = require('passport-local');
const userRoutes = require('./routes/user');

mongoose.connect("mongodb://localhost/inkers",
    { useNewUrlParser: true, useFindAndModify: false, useUnifiedTopology: true}, err => {
        if (!err) console.log("connected Successfully");
    });


app.set('views', path.join(__dirname, 'views'));
app.set("view engine","ejs");
app.use(logger('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
const keys = ["Ron", "Swanson"];
const expiryDate = new Date(5 * Date.now() + 60 * 60 * 1000); // 5 hours
// console.log(expiryDate);
app.use(
    session({
        secret: "musicala",
        resave: true,
        saveUninitialized: true,
        cookie: {
            secure: true,
            expires: expiryDate
        },
        keys: keys
    })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(function(req, res, next){
    res.locals.currentUser = req.user;
    next();
});

//routes
app.use('',userRoutes);



app.use(function (req, res, next) {
    next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.render('error');
});

module.exports = app;