const { promisify } = require('util')
const jwt = require('jsonwebtoken')
const User = require('./model.js')

//Token initialization
const createToken = id => { return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    })
}

exports.protect = async (req, res, next) => {
    //1) Get token and check if its there
    let token;
    if( req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        token = req.headers.authorization.split(' ')[1]
    }

    if(!token){
        return next(res.status(401).json({message:"You are not logged in. Please log in to gain access!"}))
    }

    //2) Verifying token 
    let decoded;
    try{
        decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET)
    } catch(err){
        return res.status(401).json({
            status: 'fail',
            message: ["Invalid token, Please log in again!"]
        })
    }

    //3) Check if user still exists
    const currentUser = await User.findById(decoded.id)
    if(!currentUser){
        return res.status(401).json({
            status:  'fail',
            message: "The user belonging to this token does not exist"
        })
    }

    //GRANT ACCESS
    req.user = currentUser
    next();
}

exports.getUsers = async (req, res, next) => {
const users = await User.find()
 res.status(200).json({
    status:'success',
    data:{
        users
    }
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

exports.login = async (req, res, next) => {
    const { email, password } = req.body
    // 1) Check if email and password exists
    if(!email || !password){
    return res.status(400).json({
            status:'fail',
            message:"Please provide email and password"
         }) 
    }

    // 2) Check if user & password exists 
    const user =  await User.findOne({email}).select('+password')
    if(!user || !await user.correctPassword(password, user.password)){
        return res.status(401).json({
            status:'fail',
            message:"Incorrect email or password"
         }) 
    }

    //3) If everything ok, send token to client
    const token = createToken(user._id);
    res.status(200).json({
        status: 'success',
        token
    })
}

exports.changePassword = async (req, res, next) => {
// 1) Get user based on the token 
let token;
    if( req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        token = req.headers.authorization.split(' ')[1]
    }

    if(!token){
        return next(res.status(401).json({message:"You are not logged in. Please log in to gain access!"}))
    }

    //2) Verifying token 
    let decoded;
    try{
        decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET)
    } catch(err){
        return res.status(401).json({
            status: 'fail',
            message: ["Invalid token, Please log in again!"]
        })
    }

    //3) Check if user still exists
    const user = await User.findById(decoded.id).select('+password')
    if(!user){
        return res.status(401).json({
            status:  'fail',
            message: "The user belonging to this token does not exist"
        })
    }
    console.log(user)
    //GRANT ACCESS
//2) Confirm existing password
if(!await user.correctPassword(req.body.oldPassword, user.password)){
    return res.status(401).json({
        status:'fail',
        message:"Incorrect password"
     }) 
}
try{
    user.password=req.body.newPassword
    user.passwordConfirm = req.body.confirmPassword

    return res.status(200).json({
        status:'success',
        message:"Password changed successfully"
     })
    await user.save();
} catch(err){
    return res.status(401).json({
        status:'fail',
        message:err
     })
}



// 2) If user has been verified, set new password
    // user.password = req.body.newPassword
    // user.passwordConfirm = req.body.passwordConfirm

// 3) Update changedPasswordAt property 


}