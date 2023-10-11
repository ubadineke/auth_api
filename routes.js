const express = require('express')
const router = express.Router()
const controller = require('./controller.js')

router.post('/signup', controller.signup)
router.post('/login', controller.login)
router.patch('/changePassword', controller.protect, controller.changePassword)
router.post('/forgotPassword', controller.forgotPassword)
router.patch('/resetPassword/:token', controller.resetPassword)
router
    .route('/')
    .get(controller.protect, controller.restrictTo('admin'), controller.getUsers)

module.exports = router;