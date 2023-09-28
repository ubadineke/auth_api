const express = require('express')
const router = express.Router()
const controller = require('./controller.js')

//router.post('/signup', controller.signup)
// router.post('/login', controller.login)

// router.post('/forgotPassword', controller.forgotPassword)
// router.patch('/resetPassword', controller.resetPassword)
router.get('/', controller.getUsers)

module.exports = router;