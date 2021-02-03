const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const morgan = require('morgan')
const errorHandler = require('./middleware/error')

const connectDB = require('./config/db')

//load env vars
dotenv.config({path: './config/config.env'})


//Connect to database
connectDB()


//route files
const auth = require('./routes/auth')


const app = express()


//cors
app.use(cors())

//body parser
app.use(express.json())

//development logging middleware
if (process.env.NODE_ENV == 'development') {
    app.use(morgan('dev'))
}




//mount routes
app.use('/api/v1/auth', auth)

app.use(errorHandler)


const PORT = process.env.PORT || 5000
const server = app.listen(PORT, () => {
    console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
})


//Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
    console.log(`Error: ${err.message}`);
    //Close server and exit process
    // server.close(() => process.exit(1))
})