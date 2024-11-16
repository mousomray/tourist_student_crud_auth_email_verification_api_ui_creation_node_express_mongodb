const UserModel = require('../../model/user');
const { comparePassword } = require('../../middleware/auth');
const sendEmailVerificationOTP = require('../../helper/sendEmailVerificationOTP');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

class uiauthcontroller {

    // For Register
    async register(req, res) {
        if (req.method === 'GET') {
            return res.render('authview/register', { user: req.user });
        }
        if (req.method === 'POST') {
            try {
                const { name, email, password } = req.body;
                if (!name || !email || !password || !req.file) {
                    return res.status(400).send('All fields are required, including an image.');
                }
                const existingUser = await UserModel.findOne({ email });
                if (existingUser) {
                    req.flash('err', 'User already exist with this email');
                    return res.redirect('/register');
                }
                if (password.length < 8) {
                    return res.status(400).send('Password should be at least 8 characters long.');
                }
                // Hash password
                const salt = bcrypt.genSaltSync(10);
                const hashedPassword = await bcrypt.hash(password, salt);
                const user = new UserModel({
                    ...req.body, password: hashedPassword, image: req.file.path
                });
                // Save user to database
                await user.save();
                sendEmailVerificationOTP(req, user)
                req.flash('sucess', 'Register Successfully OTP sent your email')
                return res.redirect('/login');
            } catch (error) {
                console.error('Error during registration:', error);
                return res.status(500).send('An unexpected error occurred.');
            }
        }
    }

    // For Login
    async login(req, res) {
        if (req.method === 'GET') {
            return res.render('authview/login', { user: req.user });
        }
        // If POST request, handle login logic
        if (req.method === 'POST') {
            try {
                const { email, password } = req.body;
                if (!email || !password) {
                    return res.status(400).send("All fields are required")
                }
                const user = await UserModel.findOne({ email });
                if (!user) {
                    req.flash('err', 'User Not Found');
                    return res.redirect('/login');
                }
                // Check if user verified
                if (!user.is_verified) {
                    req.flash('err', 'User is Not Verified');
                    return res.redirect('/login');
                }
                const isMatch = comparePassword(password, user.password);
                if (!isMatch) {
                    req.flash('err', 'Invalid Credential');
                    return res.redirect('/login');
                }
                // Generate a JWT token
                const token = jwt.sign({
                    _id: user._id,
                    name: user.name,
                    email: user.email,
                    image: user.image,
                }, process.env.API_KEY, { expiresIn: "1d" });

                // Handling token in cookie
                if (token) {
                    res.cookie('user_auth', token);
                    req.flash('sucess', 'Login Successfully')
                    return res.redirect('/dashboard');
                } else {
                    req.flash('err', 'Something went wrong')
                    return res.redirect('/login');
                }
            } catch (error) {
                console.error('Error during login:', error);
                return res.status(500).send('An unexpected error occurred');
            }
        }
    }

    // Dashboard area
    async dashboardpage(req, res) {
        try {
            const user = req.user;
            console.log("User Data:", user);
            res.render('authview/dashboard', {
                title: 'Dashboard Page',
                user: user
            });
        } catch (error) {
            res.status(500).send("Server error");
        }
    };

    // Handle Logout
    async logout(req, res) {
        res.clearCookie('user_auth');
        req.flash('sucess', 'Logout Successfully')
        return res.redirect('/login');
    }

    // Forget Password
    async forgotpassword(req, res) {
        if (req.method === 'GET') {
            return res.render('authview/forgetpassword', { user: req.user });
        }
        if (req.method === 'POST') {
            try {
                const { email, userId, newPassword, confirmPassword } = req.body;
                if (!email || !userId || !newPassword || !confirmPassword) {
                    return res.status(400).send('All fields are required.');
                }
                if (newPassword.length < 8) {
                    return res.status(400).send('New password should be at least 8 characters long.');
                }
                if (newPassword !== confirmPassword) {
                    return res.status(400).send('Passwords do not match.');
                }
                const user = await UserModel.findOne({ email, _id: userId });
                if (!user) {
                    return res.status(404).send('User not found or invalid user ID.');
                }
                const salt = bcrypt.genSaltSync(10);
                const hashedNewPassword = await bcrypt.hash(newPassword, salt);
                user.password = hashedNewPassword;
                await user.save();
                req.flash('sucess', 'Password update successfully')
                return res.redirect('/login');
            } catch (error) {
                console.error('Error updating password:', error);
                return res.status(500).send('An unexpected error occurred.');
            }
        }
    }

    // Update Password
    async updatepassword(req, res) {
        if (req.method === 'GET') {
            return res.render('authview/updatepassword', { user: req.user });
        }
        if (req.method === 'POST') {
            try {
                const userId = req.user._id; // Get user ID from token
                const { oldPassword, newPassword, confirmPassword } = req.body;
                if (!oldPassword || !newPassword || !confirmPassword) {
                    return res.status(400).send("All fields are required");
                }
                if (newPassword.length < 8) {
                    return res.status(400).send("New password should be at least 8 characters long");
                }
                if (newPassword !== confirmPassword) {
                    return res.status(400).send("Password do not match");
                }
                const user = await UserModel.findById(userId);
                if (!user) {
                    return res.status(404).send("User not found");
                }
                const isMatch = comparePassword(oldPassword, user.password);
                if (!isMatch) {
                    return res.status(400).send("Old password is incorrect");
                }
                const salt = bcrypt.genSaltSync(10);
                const hashedNewPassword = await bcrypt.hash(newPassword, salt);
                user.password = hashedNewPassword;
                await user.save();
                req.flash('sucess', 'Password update successfully')
                return res.redirect('/dashboard');
            } catch (error) {
                console.error("Error updating password:", error);
                res.status(500).send("Server error");
            }
        }
    }

    // Delete User Account
    async deleteUser(req, res) {
        if (req.method === 'GET') {
            return res.render('authview/deleteuser', { user: req.user });
        }
        if (req.method === 'POST') {
            try {
                const userId = req.user._id; // Get user ID from token
                const { password } = req.body; // Get password from request body
                if (!password) {
                    req.flash('err', 'Password is required to delete this account')
                    return res.redirect('/deleteuser');
                }
                const user = await UserModel.findById(userId);
                if (!user) {
                    req.flash('err', 'User not found')
                    return res.redirect('/deleteuser');
                }
                const isMatch = bcrypt.compareSync(password, user.password);
                if (!isMatch) {
                    req.flash('err', 'Incorrect password')
                    return res.redirect('/deleteuser');
                }
                await UserModel.findByIdAndDelete(userId);
                res.clearCookie('user_auth');
                req.flash('sucess', 'Your account sucessfully deleted')
                return res.redirect('/login');
            } catch (error) {
                console.error("Error deleting user account:", error);
                res.status(500).send("Server error");
            }
        }
    }

}

module.exports = new uiauthcontroller();
