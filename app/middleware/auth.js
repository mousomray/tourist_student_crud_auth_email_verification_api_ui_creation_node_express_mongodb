//**bcryptjs** একটি লাইব্রেরি যা পাসওয়ার্ড সুরক্ষিতভাবে হ্যাশ করতে, সাল্ট তৈরি করতে এবং আক্রমণকারীদের থেকে সুরক্ষা প্রদান করতে ব্যবহৃত হয়।

//**compareSync** মেথডটি পাসওয়ার্ড এবং হ্যাশড পাসওয়ার্ডের মধ্যে মিল আছে কিনা তা সিঙ্ক্রোনাসভাবে পরীক্ষা করার জন্য ব্যবহৃত হয়।

const bcrypt = require('bcryptjs');
const comparePassword = (password, hashPassword) => {
  return bcrypt.compareSync(password, hashPassword);
};
module.exports = { comparePassword };


