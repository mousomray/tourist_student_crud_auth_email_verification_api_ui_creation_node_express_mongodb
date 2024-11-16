const Student = require('../../model/student');

class studentuicontroller {

    // add student
    async addstudent(req, res) {
        if (req.method === 'POST') {
            try {
                const { name, course, batch_year, language, father_name, phone_no, age, gender, city, } = req.body;
                // Validate required fields
                if (!name || !course || !batch_year || !language || !father_name || !phone_no || !age || !gender || !city) {
                    return res.status(400).send('All fields are required.');
                }

                // Validate field types
                if (isNaN(Number(batch_year))) {
                    return res.status(400).send('Batch year must be a valid number.');
                }
                if (isNaN(Number(phone_no)) || String(phone_no).length !== 10) {
                    return res.status(400).send('Phone number must be a valid 10-digit number.');
                }
                if (isNaN(Number(age)) || Number(age) <= 0) {
                    return res.status(400).send('Age must be a valid positive number.');
                }
                if (!['Male', 'Female', 'Other',].includes(gender)) {
                    return res.status(400).send('Gender is Required');
                }

                // Handle checkbox for languages (can be an array or a single value)
                const languages = Array.isArray(language) ? language : [language];

                // Construct the student data according to your API format
                const studentData = {
                    name: name.trim(),
                    course: course.trim(),
                    batch_year: Number(batch_year),
                    language: languages,
                    personal_details: {
                        father_name: father_name.trim(),
                        phone_no: Number(phone_no),
                        age: Number(age),
                        gender: gender,
                        city: city.trim(),
                    },
                };
                // Save the data to the database
                const student = new Student(studentData);
                const savedData = await student.save();
                console.log("Student saved:", savedData);
                req.flash('sucess', "Student created successfully")
                return res.redirect('/studentlist');
            } catch (error) {
                console.error('Error saving student:', error);
                return res.status(500).send('Error saving student');
            }
        }

        // Render the form view
        res.render('studentview/addstudent', { user: req.user });
    }

    // Get Student List
    async getall(req, res) {
        try {
            const data = await Student.find()
            res.render('studentview/studentlist', { user: req.user, mydata: data })
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: "Error retrieving employee" });
        }
    }

    // Get Single Student 
    async singlestudent(req, res) {
        const id = req.params.id;
        try {
            const student = await Student.findById(id);
            res.render('studentview/editstudent', { user: req.user, student });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: "Error retrieving Student data" });
        }
    }

    // Update student
    async updatestudent(req, res) {
        const { id } = req.params;
        try {
            const { name, course, batch_year, language, father_name, phone_no, age, gender, city, } = req.body;
            // Validate required fields
            if (!name || !course || !batch_year || !language || !father_name || !phone_no || !age || !gender || !city) {
                return res.status(400).send('All fields are required.');
            }

            // Validate field types
            if (isNaN(Number(batch_year))) {
                return res.status(400).send('Batch year must be a valid number.');
            }
            if (isNaN(Number(phone_no)) || String(phone_no).length !== 10) {
                return res.status(400).send('Phone number must be a valid 10-digit number.');
            }
            if (isNaN(Number(age)) || Number(age) <= 0) {
                return res.status(400).send('Age must be a valid positive number.');
            }
            if (!['Male', 'Female', 'Other',].includes(gender)) {
                return res.status(400).send('Gender is Required');
            }

            // Handle checkbox for languages (can be an array or a single value)
            const languages = Array.isArray(language) ? language : [language];

            // Construct the student data according to your API format
            const studentData = {
                name: name.trim(),
                course: course.trim(),
                batch_year: Number(batch_year),
                language: languages,
                personal_details: {
                    father_name: father_name.trim(),
                    phone_no: Number(phone_no),
                    age: Number(age),
                    gender: gender,
                    city: city.trim(),
                },
            };
            // Save the data to the database
            await Student.findByIdAndUpdate(id, studentData);
            req.flash('sucess', "Student updated successfully")
            return res.redirect('/studentlist');
        } catch (error) {
            console.error('Error saving student:', error);
            return res.status(500).send('Error saving student');
        }

    }

    // Handle DELETE for delete student
    async deleteestudent(req, res) {
        const id = req.params.id;
        try {
            await Student.findByIdAndDelete(id);
            req.flash('sucess', "Student deleted successfully")
            return res.redirect('/studentlist');
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: "Error deleting student" });
        }
    }







}

module.exports = new studentuicontroller();  