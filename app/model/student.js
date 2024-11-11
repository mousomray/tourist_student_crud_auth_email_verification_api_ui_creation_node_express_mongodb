// Import mongoose
const mongoose = require('mongoose');

// Define the schema
const StudentSchema = new mongoose.Schema({
    name: {
        type: String,
        required: "Name is Required"
    },
    course: {
        type: String,
        required: "Course is Required"
    },
    batch_year: {
        type: Number,
        required: "Batch year is required"
    },
    language: {
        type: Array,
        required: "Language is Required"
    },
    personal_details: {
        father_name: {
            type: String,
            required: "Father's name is Required"
        },
        phone_no: {
            type: Number,
            required: "Phone number is Required",
            min: [1000000000, 'Phone number must be exactly 10 digits'],
            max: [9999999999, 'Phone number must be exactly 10 digits']
        },
        age: {
            type: Number,
            required: "Age is Required"
        },
        gender: {
            type: String,
            enum: ['Male', 'Female', 'Other'], // Restrict gender options
            required: "Please enter your gender",
        },
        city: {
            type: String,
            required: "City is Required"
        },
    },
}, {
    timestamps: true, // Adds createdAt and updatedAt fields
});

// Create the model
const StudentModel = mongoose.model('student', StudentSchema);

module.exports = StudentModel;