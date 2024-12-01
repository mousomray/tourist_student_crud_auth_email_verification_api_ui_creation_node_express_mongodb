const jwt = require('jsonwebtoken');

const uiAuth = (req, res, next) => {
    try {
        const token = req.cookies?.user_auth;
        if (!token) {
            req.flash('err', "You can't access that page without login")
            return res.redirect('/login'); // Redirect to login page if user is not authenticated
        }
        jwt.verify(token, process.env.API_KEY, (err, decoded) => {
            if (err) {
                req.flash('err', "Invalid or expire token please login again")
                return res.redirect('/login');
            }
            req.user = decoded;
            next();
        });
    } catch (error) {
        console.error('Error in JWT authentication middleware:', error);
        req.flash('err', "Internal server error")
        return res.redirect('/login');
    }
};

module.exports = { uiAuth };
