const express = require('express')
const routes = require('./routes.js')

const app = express();
app.use(express.json());

app.use('/api/users', routes)

module.exports = app;