const mysql = require('mysql');
const db = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: 'admin123',
    database: 'my_bd_01'
})
module.exports = db