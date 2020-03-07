const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
salt_factor = 8;

mongoose.set('useCreateIndex', true);

var userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true,
        default: 'inkers'
    },
    password: {
        type: String,
        required: true,
        default: 'inkers'
    }
});

userSchema.methods.generateHash = password => {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(salt_factor), null);
};

userSchema.methods.validPassword = password => {
    return bcrypt.compareSync(password, this.password);
};

module.exports = mongoose.model('User', userSchema);