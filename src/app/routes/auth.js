const express = require('express');
const user = express.Router();
const { isLoggedIn } = require('../middleware/middleware');
const authController = require('../controller/authcontroller');

// Register
user.get('/register', authController.renderRegister);
user.post('/register', authController.registerUser);

// Login
user.get('/login', authController.renderLogin);
user.post('/login', authController.loginUser);

// Logout
user.get('/logout', isLoggedIn, authController.logoutUser);

user.get('/', isLoggedIn, (req, res) => {
    res.render('index', {
        layout : 'layouts/main-layout',
        title : 'Home',
        user : req.user,
        showNavbar : true,
        showFooter : true
    })
})

module.exports = user;