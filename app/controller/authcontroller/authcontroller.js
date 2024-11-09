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

            //এই কোডটি bcrypt ব্যবহার করে পাসওয়ার্ডকে সুরক্ষিতভাবে হ্যাশ করে। প্রথমে একটি র‍্যান্ডম সাল্ট (এটি একটি র‍্যান্ডম ডেটা) তৈরি করা হয়, তারপর এই সাল্টকে পাসওয়ার্ডের সাথে মিলিয়ে একটি এনক্রিপ্টেড হ্যাশ তৈরি করা হয়। এর ফলে পাসওয়ার্ডটি সুরক্ষিত থাকে এবং ডাটাবেস যদি কখনো কম্প্রোমাইজড (ভেঙে পড়ে) হয়, তাও পাসওয়ার্ডটি সরাসরি এক্সপোজ (পাঠানো) করা যাবে না।
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
            // Token Fit in Header
            const token = req.headers['x-access-token'];
            console.log("Received Token:", token);
            if (!token) {
                return res.status(401).json({
                    message: "Access denied. No token provided."
                });
            }
            try {
                const decoded = jwt.verify(token, process.env.API_KEY);
                console.log("Decoded Token:", decoded);
                res.status(200).json({
                    message: "Welcome to user dashboard",
                    user: decoded
                });
            } catch (err) {
                console.log("JWT Error:", err.message);
                return res.status(401).json({
                    message: "Invalid or expired token."
                });
            }
        } catch (err) {
            console.error("Server Error:", err.message);
            res.status(500).json({
                message: "Server error"
            });
        }
    }

}
module.exports = new authcontroller()