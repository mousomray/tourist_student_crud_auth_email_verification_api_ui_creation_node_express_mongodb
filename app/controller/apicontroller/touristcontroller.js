const Tourist = require('../../model/tourist');

class touristcontroller {

    // Create API 
    async create(req, res) {
        try {
            // This code is for uploading image with validation
            if (!req.file) {
                return res.status(400).json({
                    message: "Validation error",
                    errors: ["Please enter image it is required"]
                });
            }
            const touristdata = new Tourist({ ...req.body, image: req.file.path }); // Assign the image path for validation
            const data = await touristdata.save();
            res.status(201).json({ message: "Tourist added successfully", data });
        } catch (error) {
            const statusCode = error.name === 'ValidationError' ? 400 : 500;
            const message = error.name === 'ValidationError'
                ? { message: "Validation error", errors: Object.values(error.errors).map(err => err.message) }
                : { message: "An unexpected error occurred" };

            console.error(error);
            res.status(statusCode).json(message);
        }
    }

    // Get API 
    async getall(req, res) {
        try {
            const data = await Tourist.find()
            res.status(200).json({
                message: "Tourist get successfully",
                total: data.length,
                tourists: data
            })
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: "Error retrieving tourist data" });
        }
    }

    // Get Single 
    async getsingle(req, res) {
        const id = req.params.id;
        try {
            const data = await Tourist.findById(id);
            if (data) {
                res.status(200).json(data);
            } else {
                res.status(404).json({ message: "Tourist not found" });
            }
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: "Error retrieving Tourist data" });
        }
    }

    // Update Data
    async touristupdate(req, res) {
        const id = req.params.id;
        try {
            const updatedtourist = await Tourist.findByIdAndUpdate(id, req.body, { new: true, runValidators: true }
            );
            // File Handling Area
            if (req.file) {
                updatedtourist.image = req.file.path
                await updatedtourist.save(); // Save the document with the updated image
            }
            if (!updatedtourist) {
                return res.status(404).json({ message: "Tourist not found" });
            }
            res.status(200).json({ message: "Tourist updated successfully", data: updatedtourist });
        } catch (error) {
            const statusCode = error.name === 'ValidationError' ? 400 : 500;
            const message = error.name === 'ValidationError'
                ? { message: "Validation error", errors: Object.values(error.errors).map(err => err.message) }
                : { message: "Error updating Tourist data" };

            console.error(error);
            res.status(statusCode).json(message);
        }
    }

    // Delete Tourist
    async touristdelete(req, res) {
        const id = req.params.id;
        try {
            const deletedtourist = await Tourist.findByIdAndDelete(id);
            res.status(deletedtourist ? 200 : 404).json(
                deletedtourist ? { message: "Tourist deleted successfully", delete: deletedtourist } : { message: "Tourist not found" }
            );
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: "Error deleting tourist" });
        }
    }

}
module.exports = new touristcontroller()






