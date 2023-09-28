exports.getUsers = (req, res, next) => {
console.log('worked')
 res.status(200).json({
    status:'success',
    message:"no defined message on route yet "
 })
}