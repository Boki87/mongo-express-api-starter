const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please add name']
    },
    email: {
        type: String,
        required: [true, 'Please add email']
    },
    password: {
        type: String,
        required: [true, 'Please add password'],
        minlength: [6, 'Password must be at least 6 characters long'],
        select: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
})


//Encrypt password using bcrypt
//static method called on the model
UserSchema.pre('save', async function (next) {

    if (!this.isModified('password')) {
        next()
    }

    const salt = await bcrypt.genSalt(10)
    this.password = await bcrypt.hash(this.password, salt)

})


//sign jwt and return it
UserSchema.methods.getSignedJwtToken = function () {
    return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE   
    })
}

//match user password to hashed password in db
UserSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password)
}


module.exports = mongoose.model('User', UserSchema)