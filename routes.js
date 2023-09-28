const express = require('express')
const router = express.Router()
const controller = require('./controller.js')

router.post('/signup', controller.signup)
router.post('/login', controller.login)
router.patch('/changePassword', controller.changePassword)
// router.post('/forgotPassword', controller.forgotPassword)
// router.patch('/resetPassword', controller.resetPassword)
router
    .route('/')
    .get(controller.protect, controller.getUsers)

module.exports = router;