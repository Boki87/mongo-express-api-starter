const User = require('../models/user')
const asyncHandler = require('../middleware/async')
const ErrorResponse = require('../utils/errorResponse')

// @desc        Register user
// @route       POST /api/v1/auth/register
// @access      Public
exports.register = asyncHandler( async (req, res, next) => {

    const { name, email, password } = req.body
    

    if (!email || !password || !name) {
        return next(new ErrorResponse(`Please provide an email, name and password`, 400))
    }

    //create user
    const user = await User.create({
        name, email, password
    })


    sendTokenResponse(user, 200, res)

})

exports.login = asyncHandler(async (req, res, next) => {

    const { email, password } = req.body
    
    //validate email and password
    if (!email || !password) {
        return next(new ErrorResponse(`Please provide an email and password`, 400))
    }

    //check for user
    const user = await User.findOne({ email }).select('+password') // using + to override default select: false on model
    
    if (!user) {
        return next(new ErrorResponse(`Invalid credentials`, 401))
    }

    //check if password matches
    const isMatch = await user.matchPassword(password)

    if (!isMatch) {
        return next(new ErrorResponse(`Invalid credentials`, 401))
    }

    sendTokenResponse(user, 200, res)

})




//get token from model, create token and send response
const sendTokenResponse = (user, statusCode, res) => {


    //create token
    const token = user.getSignedJwtToken()

    const options = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
        httpOnly: true
    }

    res.status(statusCode)
    .json({
            success: true,
            token
    })

}