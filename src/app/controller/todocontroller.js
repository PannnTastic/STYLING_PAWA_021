const bcrypt = require('bcryptjs')
const db = require('../infrastructure/database/connection');
const responsAPI = require('../infrastructure/response');

exports.authUser = (req,res) => {
    const user = req.session.userId

    if (!user) {
        return responsAPI( 401, 'Unauthorized', 'Invalid',res);
    }
    const sql = 'select * from todo where id_user = ?';
    db.query(sql, [user], (err, result) => {
        if (err) {
            return responsAPI(500, 'Internal Server Error','Invalid',res);
        };
        if (result.length === 0) {
            res.render('todo',{
                title: 'Todo List',
                todo: result,
                user: req.session.username,
                layout : 'layouts/main-layout',
                showNavbar : true,
                showFooter : true
            });
        }
        res.render('todo',{
            title: 'Todo List',
            todo: result,
            user: req.session.username,
            layout : 'layouts/main-layout',
            showNavbar : true,
            showFooter : true
        });
    });  
};



exports.addTodo = (req, res) => {
    const user = req.session.userId
    const { title, description } = req.body;
    const sql = 'insert into todo (judul,deskripsi,id_user) values (?,?,?)'
    db.query(sql, [title, description,user], (err, result) => {
        if (err) {
            return responsAPI(500, err,'Error Occured',res);
        }
        res.redirect('/todos')
        
        
    });
};

exports.markDone = (req,res) => {
    const {id} = req.params
    const sql = 'UPDATE todo SET done = 1 WHERE id_todo =?'
    db.query(sql, [id], (err, result) => {
        if (err) {
            return responsAPI( 500, 'Internal Server Error','Error Occured',res);
        }
        if (result.affectedRows === 0) {
            return responsAPI(404, 'Todo not found','No Todo Found',res);
        }
        
        res.redirect('/todos')
        
    });
};

exports.unDone = (req,res) => {
    const {id} = req.params
    const sql = 'UPDATE todo SET done = 0 WHERE id_todo =?'
    db.query(sql, [id], (err, result) => {
        if (err) {
            return responsAPI(500, 'Internal Server Error','Error Occured',res);
        }
        if (result.affectedRows === 0) {
            return responsAPI(404, 'Todo not found','No Todo Found',res);
        }
        res.redirect('/todos')
        
    });
}

exports.deleteTodo = (req, res) => {
    const {id} = req.params
    const sql = 'DELETE FROM todo WHERE id_todo =?'
    db.query(sql, [id], (err, result) => {
        if (err) {
            return responsAPI(500, 'Internal Server Error','Error Occured',res);
        }
        if (result.affectedRows === 0) {
            return responsAPI(404, 'Todo not found','No Data Found',res);
        }
        res.redirect('/todos')
           
    });
};

exports.updateTodo = (req, res) => {
    const {id} = req.body
    const {title, description } = req.body;
    const sql = 'UPDATE todo SET judul =?, deskripsi =? WHERE id_todo =?'
    db.query(sql, [title, description, id], (err, result) => {
        if (err) {
            return responsAPI(500, 'Internal Server Error','Error Occured',res);
        }
        if (result.affectedRows === 0) {
            return responsAPI(404, 'Todo not found','No Data found',res);
        }
        res.redirect('/todos')
        
        
    });
}