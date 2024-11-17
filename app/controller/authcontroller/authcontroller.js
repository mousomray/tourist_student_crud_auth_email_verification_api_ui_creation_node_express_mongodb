const UserModel = require('../../model/user') // Our user Model
const EmailVerifyModel = require('../../model/otpverify')
const sendEmailVerificationOTP = require('../../helper/sendEmailVerificationOTP');
const transporter = require('../../config/emailtransporter')
const { comparePassword } = require('../../middleware/auth') // Came from middleware folder
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
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);
            const user = new UserModel({
                ...req.body, password: hashedPassword, image: req.file.path
            });
            const savedUser = await user.save();
            // Sent OTP after successfull register
            sendEmailVerificationOTP(req, user)
            res.status(201).json({
                message: "Registration successfull and send otp in your email id",
                user: savedUser
            })
        } catch (error) {
            const statusCode = error.name === 'ValidationError' ? 400 : 500;
            const message = error.name === 'ValidationError'
                ? { message: "Validation error", errors: Object.values(error.errors).map(err => err.message) }
                : { message: "An unexpected error occurred" }; // Other Field validation
            console.error(error);
            res.status(statusCode).json(message);
        }
    }


    // Verify OTP
    async verifyOtp(req, res) {
        try {
            const { email, otp } = req.body;
            if (!email || !otp) {
                return res.status(400).json({ status: false, message: "All fields are required" });
            }
            const existingUser = await UserModel.findOne({ email });
            if (!existingUser) {
                return res.status(404).json({ status: "failed", message: "Email doesn't exists" });
            }
            if (existingUser.is_verified) {
                return res.status(400).json({ status: false, message: "Email is already verified" });
            }
            const emailVerification = await EmailVerifyModel.findOne({ userId: existingUser._id, otp });
            if (!emailVerification) {
                if (!existingUser.is_verified) {
                    await sendEmailVerificationOTP(req, existingUser);
                    return res.status(400).json({ status: false, message: "Invalid OTP, new OTP sent to your email" });
                }
                return res.status(400).json({ status: false, message: "Invalid OTP" });
            }
            // Check if OTP is expired
            const currentTime = new Date();
            // 15 * 60 * 1000 calculates the expiration period in milliseconds(15 minutes).
            const expirationTime = new Date(emailVerification.createdAt.getTime() + 15 * 60 * 1000);
            if (currentTime > expirationTime) {
                // OTP expired, send new OTP
                await sendEmailVerificationOTP(req, existingUser);
                return res.status(400).json({ status: "failed", message: "OTP expired, new OTP sent to your email" });
            }
            // OTP is valid and not expired, mark email as verified
            existingUser.is_verified = true;
            await existingUser.save();

            // Delete email verification document
            await EmailVerifyModel.deleteMany({ userId: existingUser._id });
            return res.status(200).json({ status: true, message: "Email verified successfully" });
        } catch (error) {
            console.error(error);
            res.status(500).json({ status: false, message: "Unable to verify email, please try again later" });
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
            // Check if user verified
            if (!user.is_verified) {
                return res.status(401).json({ status: false, message: "Your account is not verified" });
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
                image: user.image
            }, process.env.API_KEY,
                { expiresIn: "1d" })
            res.status(200).json({
                message: "User login successfully",
                data: {
                    _id: user._id,
                    name: user.name,
                    email: user.email,
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
    };

    // Update Password
    async updatePassword(req, res) {
        try {
            const userId = req.user._id; // Get user ID from token
            const { oldPassword, newPassword, confirmPassword } = req.body;
            if (!oldPassword || !newPassword || !confirmPassword) {
                return res.status(400).json({
                    message: "All fields are required"
                });
            }
            if (newPassword.length < 8) {
                return res.status(400).json({
                    message: "New password should be at least 8 characters long"
                });
            }
            if (newPassword !== confirmPassword) {
                return res.status(400).json({
                    message: "Password do not match"
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

    // Reset Password link 
    async resetpasswordlink(req, res) {
        try {
            const { email } = req.body;
            if (!email) {
                return res.status(400).json({ status: false, message: "Email field is required" });
            }
            const user = await UserModel.findOne({ email });
            if (!user) {
                return res.status(404).json({ status: false, message: "Email doesn't exist" });
            }
            // Generate token for password reset
            const secret = user._id + process.env.API_KEY;
            const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '20m' });
            console.log("My forget token...", token)
            // Reset Link and this link generate by frontend developer
            // FRONTEND_HOST_FORGETPASSWORD = http://localhost:3004/forgetpassword
            const resetLink = `${process.env.FRONTEND_HOST_FORGETPASSWORD}/${user._id}/${token}`;
            // Send password reset email  
            await transporter.sendMail({
                from: process.env.EMAIL_FROM,
                to: user.email,
                subject: "Password Reset Link",
                html: `<p>Hello ${user.name},</p><p>Please <a href="${resetLink}">Click here</a> to reset your password.</p>`
            });
            // Send success response
            res.status(200).json({ status: true, message: "Password reset email sent. Please check your email." });

        } catch (error) {
            console.log(error);
            res.status(500).json({ status: false, message: "Unable to send password reset email. Please try again later." });

        }

    }

    // Forget Password 
    async forgetPassword(req, res) {
        try {
            const { id, token } = req.params;
            const { password, confirmPassword } = req.body;
            const user = await UserModel.findById(id);
            if (!user) {
                return res.status(404).json({ status: false, message: "User not found" });
            }
            // Validate token check 
            const new_secret = user._id + process.env.API_KEY;
            jwt.verify(token, new_secret);

            if (!password || !confirmPassword) {
                return res.status(400).json({ status: false, message: "New Password and Confirm New Password are required" });
            }

            if (password !== confirmPassword) {
                return res.status(400).json({ status: false, message: "New Password and Confirm New Password don't match" });
            }
            // Generate salt and hash new password
            const salt = await bcrypt.genSalt(10);
            const newHashPassword = await bcrypt.hash(password, salt);

            // Update user's password
            await UserModel.findByIdAndUpdate(user._id, { $set: { password: newHashPassword } });

            // Send success response
            res.status(200).json({ status: "success", message: "Password reset successfully" });

        } catch (error) {
            console.log("Error updating password...", error)
            return res.status(500).json({ status: "failed", message: "Unable to reset password. Please try again later." });
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