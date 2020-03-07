const Promise = require('bluebird');
const User = require('../models/user');

module.exports.getUser = () => {
    return new Promise((resolve, reject) => {
        try{
            User.find({})
            .exec()
            .then(users => {
                return resolve(users);
            })
            .catch(err => reject(err));
        } catch(error){
            return reject(error);
        }
    });
};

module.exports.addUser = (userDetails) => {
    return new Promise((resolve, reject) => {
        try{
            User.find({email: userDetails.email})
            .exec()
            .then(user => {
                console.log('query success');
                console.log(user);
                // if(message!=='ok') return resolve(message);
                let newUser = new User(userDetails);
                newUser.email = userDetails.email;
                newUser.password = newUser.generateHash(userDetails.password);
                console.log(newUser);
                newUser.save().then(savedUser => resolve('ok'));
            })
            .catch(err => reject(err));
        } catch(error){
            console.log(error);
            return reject(error);
        }
    })
}

module.exports.deleteUser = id => {
    return new Promise((resolve, reject) => {
        try {
            User.findOne({
                _id: id
            })
                .exec()
                .then(user => {
                    if (!user) {
                        return reject(new Error("User doesn't exist"));
                    }
                    user
                        .remove()
                        .then(() => resolve())
                        .catch(err => reject(err));
                })
                .catch(err => reject(err));
        } catch (error) {
            return reject(error);
        }
    });
};

module.exports.updateUser = userDetails => {
    return new Promise((resolve, reject) => {
        try {
            return User.findByIdAndUpdate(
                userDetails._id,
                { $set: userDetails },
                { new: true }
            )
                .exec()
                .then(user => {
                    if (!user) {
                        return reject(new Error("User not found"));
                    }
                    return resolve(user);
                })
                .catch(err => reject(err));
        } catch (error) {
            return reject(error);
        }
    });
};