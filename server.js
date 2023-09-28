const mongoose = require('mongoose')
const dotenv = require('dotenv');

dotenv.config({ path: './config.env' })
const app = require('./app')

//Connect DB
const DB = process.env.DATABASE_LOCAL

mongoose.connect(DB).then(con => {
    //console.log(con.connections);
    console.log('DB connection successful!')
})


//Start Server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`App running on port ${port}...`)
})