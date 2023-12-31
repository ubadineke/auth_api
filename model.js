const crypto = require('crypto')
const mongoose = require('mongoose')
const validator = require('validator');
const bcrypt = require('bcryptjs')
//name, email, role, password, passwordConfirm

const userSchema = new mongoose.Schema({
    name: {
        type: String, 
        required: [true, "Please provide your name"]
    },
    email: {
        type: String, 
        required: [true, "Please provide your email address"],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    role:{
        type: String, 
        enum: ['user', 'admin'],
        default:'user'
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: 8,
        select: false
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Please confirm your password'],
        validate: {
            //This only works on CREATE AND SAVE!
            validator: function(el) {
            return el === this.password;
            },
            message: 'Passwords are not the same!'
        },
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date
})

//Hash Password 
userSchema.pre('save', async function(next){
    //ONly run this function if password was actually modified
    if(!this.isModified('password')) return next();

    //Hash the password with cost of 12
    this.password =  await bcrypt.hash(this.password, 12)

    //Delete passwordConfirm field 
    this.passwordConfirm = undefined;
    next();
});

//Creating an instance
userSchema.methods.correctPassword = async function(incomingPassword, storedPassword){
    return await bcrypt.compare(incomingPassword, storedPassword)
};

userSchema.methods.changedPasswordAfter = function(JWTTimestamp){
    if(this.passwordChangedAt){
     const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10)
        return JWTTimestamp < changedTimestamp;
    }
    return false;
}

userSchema.methods.createPasswordResetToken = function(){
    const resetToken = crypto.randomBytes(32).toString('hex')
   
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex')
 //console.log({resetToken}, this.passwordResetToken)
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000
    return resetToken;
}

const User = mongoose.model('User', userSchema)
module.exports = User