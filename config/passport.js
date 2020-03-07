const passportStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const User = require("../models/user");


module.exports = passport => {
    passport.serializeUser((user, done) => done(null, user.id));

    passport.deserializeUser((id, done) => {
        User.findById(id)
            .exec()
            .then(user => done(null, user))
            .catch(err => done(err));
    });

    passport.use(
        "login",
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
}