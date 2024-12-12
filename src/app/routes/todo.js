const express = require('express');
const todo = express.Router();
const { isLoggedIn } = require('../middleware/middleware');
const todocontroller = require('../controller/todocontroller');

todo.get('/', isLoggedIn, todocontroller.authUser);
todo.post('/add',todocontroller.addTodo);

todo.post('/done/:id',todocontroller.markDone);
todo.post('/undone/:id',todocontroller.unDone)

todo.post('/delete/:id',todocontroller.deleteTodo);

todo.post('/edit',todocontroller.updateTodo)



todo.get('/', isLoggedIn, (req, res) => {
    res.render('index', {
        layout : 'layouts/main-layout',
        title : 'Home',
        user : req.session.username,
        showNavbar : true,
        showFooter : true
    })
})


module.exports = todo;