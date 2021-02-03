const ErrorResponse = require('../utils/errorResponse')

const errorHandler = (err, req, res, next) => {

    let error = {...err}
    error.message = err.message


    //log to console for developer
    // console.log(err.stack);
    // console.log(err.name);
    console.log(err);


    //Mongoose bad ObjectId, objectId not formatted as should
    if(err.name == 'CastError') {
        const message = `Resource not found with id of ${err.value}`
        error = new ErrorResponse(message, 404)
    }
    
    //Mongoose duplicate key error , something exists with the same key in the db
    if(err.code == 11000) { //code for duplicate key
        const message = `Duplicate field value entered`
        error = new ErrorResponse(message, 404)
    }


    // Mongoose validation error
    if(err.name == 'ValidationError') {
        const message = Object.values(err.errors).map(val => val.message)
        error = new ErrorResponse(message, 400)
    }



    res.status(error.statusCode || 500).json({
        success: false,
        error: error.message || 'Server Error'
    })
}

module.exports = errorHandler