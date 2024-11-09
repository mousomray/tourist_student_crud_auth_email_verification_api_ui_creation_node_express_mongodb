const mongoose = require('mongoose')
const Schema = mongoose.Schema


const TouristSchema = new Schema({
    name: {
        type: String,
        required: "Name is Required"
    },
    phone: {
        type: Number,
        required: "Phone number is Required",
        min: [1000000000, 'Phone number must be exactly 10 digits'],
        max: [9999999999, 'Phone number must be exactly 10 digits']
    },
    city: {
        type: String,
        required: "City is Required"
    },
    address: {
        type: String,
        required: "Address is Required"
    },
    image: {
        type: String,
        required: "Image is required"
    }


})

const TouristModel = mongoose.model('tourist', TouristSchema);

module.exports = TouristModel;

