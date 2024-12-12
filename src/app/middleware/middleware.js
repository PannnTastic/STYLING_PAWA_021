function isLoggedIn(req, res, next) {
    console.log('Checking session for userId:', req.session.userId);
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}
  
  module.exports = {isLoggedIn};