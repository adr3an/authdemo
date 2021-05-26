const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "username cannot be empty"]
    },
    password: {
        type: String,
        required: [true, "password cannot be empty"]
    }
});

userSchema.statics.findAndValidate = async function (username, pw) {
    const foundUser = await this.findOne({ username });
    const isValid = await bcrypt.compare(pw, foundUser.password);
    return isValid ? foundUser : false;
}

userSchema.pre('save', async function (next) {
  if(!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

module.exports = mongoose.model('User', userSchema);