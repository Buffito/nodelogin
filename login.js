require("dotenv").config()

const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const validator = require("email-validator");

const DB_HOST = process.env.DB_HOST
const DB_USER = process.env.DB_USER
const DB_PASSWORD = process.env.DB_PASSWORD
const DB_DATABASE = process.env.DB_DATABASE

const pool = mysql.createPool({
    connectionLimit : 10,
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE
});

const app = express();

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));
app.use(express.static(path.join(__dirname, 'static')));

app.get('/', function (request, response) {
    response.sendFile(path.join(__dirname + '/login.html'))
});

app.get('/create', function (request, response) {
    response.sendFile(path.join(__dirname + '/create.html'))
});


app.post("/auth", async (request, response) => {
    let username = request.body.username;
    let hashedPassword = await bcrypt.hash(req.body.password, 10);
    pool.getConnection(async (error, connection) => {
        if (error) throw (error)
        const sqlSelect = "SELECT * FROM accounts WHERE username = ? AND password = ?";
        const selectQuery = mysql.format(sqlSelect, [username, hashedPassword]);
        await connection.query(selectQuery, (error, results) => {
            if (error) throw error;

            if (results.length > 0) {

                request.session.loggedin = true;
                request.session.username = username;

                response.redirect('/home');
            } else {
                response.send('Incorrect Username and/or Password!');
            }
            response.end();
        });
        connection.release();
    });
});

app.post("/register", async (request, response) => {
    let username = request.body.username;
    let hashedPassword = await bcrypt.hash(request.body.password, 10);
    let email = "";
    if (validator.validate(request.body.email)) {
        email = request.body.email;
    } else {
        response.status(400).send('Invalid Email');
    }

    pool.getConnection(async (error, connection) => {
        const sqlInsert = "INSERT INTO accounts VALUES (?,?,?)";
        const insertQuery = mysql.format(sqlInsert, [username, hashedPassword, email]);
        await connection.query(insertQuery, (error, results) => {
            if (error) throw error;

            request.session.loggedin = true;
            request.session.username = username;

            response.redirect('/home');
            response.end();
        })
        connection.release();
    })
});



app.get('/home', function (request, response) {

    if (request.session.loggedin) {
        response.send('Welcome, ' + request.session.username + '!');
    } else {
        response.send('Please login to view this page!');
    }

    response.end();
});

const host = process.env.DB_HOST;
const port = process.env.PORT;

app.listen(port,
    () => console.log(`Server Started on http://${host}:${port}`));