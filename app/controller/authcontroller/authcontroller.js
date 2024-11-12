const { comparePassword } = require('../../middleware/auth') // Came from middleware folder
const UserModel = require('../../model/user') // Our user Model
const jwt = require('jsonwebtoken'); // For to add token in header
const bcrypt = require('bcryptjs'); // For hashing password

class authcontroller {

    // Handle Register
    async register(req, res) {
        try {
            // Find email from database
            const existingUser = await UserModel.findOne({ email: req.body.email });
            // Same email not accpected
            if (existingUser) {
                return res.status(400).json({
                    message: "Validation error",
                    errors: ["User already exists with this email"]
                });
            }
            // Password Validation
            if (!req.body.password) {
                return res.status(400).json({
                    message: "Validation error",
                    errors: ["Password is required"]
                });
            }
            if (req.body.password.length < 8) {
                return res.status(400).json({
                    message: "Validation error",
                    errors: ["Password should be at least 8 characters long"]
                });
            }
            // Image Path Validation
            if (!req.file) {
                return res.status(400).json({
                    message: "Validation error",
                    errors: ["Profile image is required"]
                });
            }

            // Change password to hashing 
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);

            const user = new UserModel({
                ...req.body, password: hashedPassword, image: req.file.path
            });
            const savedUser = await user.save();
            res.status(201).json({
                message: "User created successfully", data: savedUser
            });
        } catch (error) {
            const statusCode = error.name === 'ValidationError' ? 400 : 500;
            const message = error.name === 'ValidationError'
                ? { message: "Validation error", errors: Object.values(error.errors).map(err => err.message) }
                : { message: "An unexpected error occurred" }; // Other Field validation
            console.error(error);
            res.status(statusCode).json(message);
        }
    }



    // Handle Login
    async login(req, res) {
        try {
            const { email, password } = req.body
            if (!email || !password) {
                return res.status(400).json({
                    message: "All fields are required"
                })
            }
            const user = await UserModel.findOne({ email })
            if (!user) {
                return res.status(400).json({
                    message: "User not found"
                })
            }
            const isMatch = comparePassword(password, user.password)
            if (!isMatch) {
                return res.status(400).json({
                    message: "Invalid credentials"
                })
            }
            const token = jwt.sign({
                _id: user._id,
                name: user.name,
                email: user.email,
                image: user.image,
                password: user.password
            }, process.env.API_KEY,
                { expiresIn: "1d" })
            res.status(200).json({
                message: "User login successfully",
                data: {
                    _id: user._id,
                    name: user.name,
                    email: user.email,
                    password: user.password,
                    image: user.image
                },
                token: token
            })
        } catch (error) {
            console.log(error);

        }

    }

    // Fetching Dashboard Data 
    async dashboard(req, res) {
        try {
            const user = req.user;
            if (!user) {
                return res.status(401).json({ message: "Unauthorized access. No user information found." });
            }
            console.log("User Data:", user);
            res.status(200).json({
                message: "Welcome to the user dashboard",
                user: user
            });
        } catch (error) {
            console.error("Server Error:", error.message);
            res.status(500).json({ message: "Server error" });
        }
    }

    // Update Password
    async updatePassword(req, res) {
        try {
            const userId = req.user._id; // Get user ID from token
            const { oldPassword, newPassword } = req.body;
            if (!oldPassword || !newPassword) {
                return res.status(400).json({
                    message: "Both old password and new password are required"
                });
            }
            if (newPassword.length < 8) {
                return res.status(400).json({
                    message: "New password should be at least 8 characters long"
                });
            }
            const user = await UserModel.findById(userId);
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
            const isMatch = comparePassword(oldPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: "Old password is incorrect" });
            }
            const salt = bcrypt.genSaltSync(10);
            const hashedNewPassword = await bcrypt.hash(newPassword, salt);
            user.password = hashedNewPassword;
            await user.save();
            res.status(200).json({ success: true, message: "Password updated successfully" });
        } catch (error) {
            console.error("Error updating password:", error);
            res.status(500).json({ message: "Server error" });
        }
    }

    // Forget Password 
    async forgotPassword(req, res) {
        try {
            const { email, userId, newPassword } = req.body;
            if (!email || !userId || !newPassword) {
                return res.status(400).json({
                    message: "Email, userId, and newPassword are required"
                });
            }
            if (newPassword.length < 8) {
                return res.status(400).json({
                    message: "New password should be at least 8 characters long"
                });
            }
            const user = await UserModel.findOne({ email, _id: userId });
            if (!user) {
                return res.status(404).json({ message: "User not found or invalid user ID" });
            }
            const salt = bcrypt.genSaltSync(10);
            const hashedNewPassword = await bcrypt.hash(newPassword, salt);
            user.password = hashedNewPassword;
            await user.save();
            res.status(200).json({ success: true, message: "Password updated successfully" });
        } catch (error) {
            console.error("Error updating password:", error);
            res.status(500).json({ message: "Server error" });
        }
    }

    // Delete User Account
    async deleteUser(req, res) {
        try {
            const userId = req.user._id; // Get user ID from token
            const { password } = req.body; // Get password from request body
            if (!password) {
                return res.status(400).json({ message: "Password is required to delete the account" });
            }
            const user = await UserModel.findById(userId);
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
            const isMatch = bcrypt.compareSync(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: "Incorrect password" });
            }
            await UserModel.findByIdAndDelete(userId);
            res.status(200).json({ success: true, message: "User account deleted successfully" });
        } catch (error) {
            console.error("Error deleting user account:", error);
            res.status(500).json({ message: "Server error" });
        }
    }

}
module.exports = new authcontroller()