const asyncHandler = fn => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next)
}

/*
the same as

const asyncHandler = (fn) => {
    return Promise.resolve(fn()).catch(fn({next}))
}


*/
module.exports = asyncHandler