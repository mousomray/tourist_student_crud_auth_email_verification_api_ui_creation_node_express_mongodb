const Student = require('../../model/student');

class studentcontroller {

    // Create Student Data 
    async create(req, res) {
        try {
            const studentdata = new Student(req.body); 
            const data = await studentdata.save();
            res.status(201).json({ message: "Student added successfully", data });
        } catch (error) {
            const statusCode = error.name === 'ValidationError' ? 400 : 500;
            const message = error.name === 'ValidationError'
                ? { message: "Validation error", errors: Object.values(error.errors).map(err => err.message) }
                : { message: "An unexpected error occurred" };

            console.error(error);
            res.status(statusCode).json(message);
        }
    }

    // Get Student List
    async getall(req, res) {
        try {
            const data = await Student.find()
            res.status(200).json({
                message: "Student get successfully",
                total: data.length,
                students: data
            })
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: "Error retrieving student data" });
        }
    }

    // Get Single Student 
    async getsingle(req, res) {
        const id = req.params.id;
        try {
            const data = await Student.findById(id);
            if (data) {
                res.status(200).json(data);
            } else {
                res.status(404).json({ message: "Student not found" });
            }
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: "Error retrieving Student data" });
        }
    }

    // Update Student
    async studentupdate(req, res) {
        const id = req.params.id;
        try {
            const updatedstudent = await Student.findByIdAndUpdate(id, req.body, { new: true, runValidators: true }
            );
            if (!updatedstudent) {
                return res.status(404).json({ message: "Student not found" });
            }
            res.status(200).json({ message: "Student updated successfully", data: updatedstudent });
        } catch (error) {
            const statusCode = error.name === 'ValidationError' ? 400 : 500;
            const message = error.name === 'ValidationError'
                ? { message: "Validation error", errors: Object.values(error.errors).map(err => err.message) }
                : { message: "Error updating Student data" };

            console.error(error);
            res.status(statusCode).json(message);
        }
    }

    // Delete Student
    async studentdelete(req, res) {
        const id = req.params.id;
        try {
            const deletedstudent = await Student.findByIdAndDelete(id);
            res.status(deletedstudent ? 200 : 404).json(
                deletedstudent ? { message: "Student deleted successfully", delete: deletedstudent } : { message: "Student not found" }
            );
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: "Error deleting student" });
        }
    }

}
module.exports = new studentcontroller()