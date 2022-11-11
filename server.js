if(process.env.NODE_ENV !== 'production') {
    require("dotenv").config();
}
const express = require("express");
const mongoose = require("mongoose");
const passport = require('passport');
const bcrypt = require('bcrypt');
const flash = require('express-flash');
const session = require('express-session');
const cookieParser = require('cookie-parser')
const userAuth = require('./models/userAuth');
const initPassport = require('./passport-config');
const app = express();
const port = 3033;

initPassport(passport, userAuth);

//database
mongoose.connect(process.env.DB_URL);
const db = mongoose.connection;
db.on("error", err => console.error(err));
db.on("open", () => console.log("connected to database"));

//middleware
app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());


//  routes
app.get('/login', isNotAuthenticated, (req, res) => {
    res.render("login.ejs");
})
app.get('/register',isNotAuthenticated, (req, res) => {
    res.render("register.ejs");
})
app.get('/', isAuthenticated ,(req, res)=>{
    res.render("user.ejs", {username: req.user.username});
});
app.get('/auth/register', isNotAuthenticated, (req, res)=>{
    res.sendStatus(403);
});
app.get('/auth/login', isNotAuthenticated, (req, res)=>{
    res.sendStatus(403);
});
app.post('/auth/register',isNotAuthenticated, isUnique, async  (req, res)=>{
    console.log(req)
    
    let newuser;
    try{
        const hashedPwd = await hashit(req.body.password);
        const user = new userAuth({
            username: req.body.username,
            password: hashedPwd
        })
        newuser = await user.save();
        respond(res,201, newuser);
    }catch(err){
        respond(res, 400, {message: err.message})
    }
});
app.post('/auth/login',isNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

function findUser(username){
    return userAuth.findOne({username: username});
}

function getuser(req, res, next) {
    findUser(req.body.username)
    next();
}
async function isUnique(req, res, next) {
    console.log(req)
    try{
        const users = await fetchUsers();
        const user = req.body.username;
        if (users.find(data=> data.username === user)){
            return respond(res, 400, {message: "User already exists"})
        }
    }catch(err){
        return respond(res, 500, {message: err.message})
    }
    next();
}

function hashit(password){
    return bcrypt.hash(password, 10);
}

function fetchUsers(){
    return userAuth.find();
}
function respond(res, code , message){
    res.status(code).json(message);
}

function isAuthenticated(req, res, next){
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function isNotAuthenticated(req, res, next){
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}

//start listening
app.listen(port,()=>{
    console.log(`listening on http://localhost:${port}`)
});