const jwt = require('jsonwebtoken')
const User = require('./model.js')

//Token initialization
const createToken = id => { return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    })
}


exports.getUsers = (req, res, next) => {
console.log('worked')
 res.status(200).json({
    status:'success',
    message:"no defined message on route yet "
 })
}

exports.signup = async (req, res, next) => {
    try{
        const newUser = await User.create({
            name: req.body.name,
            email: req.body.email, 
            password: req.body.password,
            passwordConfirm: req.body.passwordConfirm,
            role: req.body.role,
            passwordChangedAt: Date.now()
        });
  
        const token = createToken(newUser._id)
        res.status(200).json({
            status:'success',
            token,
            data: {
                user: newUser
            }
         })
    } catch(err){
        res.status(404).json({
            status:'fail',
            message: err
         })
    }
}