const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const router = express.Router();
const db = new sqlite3.Database('db/database.db');

// Route to create a new booking
router.post('/', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }

  const { date, startTime, endTime, instructor_name } = req.body;
  const studentEmail = req.session.user.email;

  try {
    // Get student ID from the session user
    const student = await new Promise((resolve, reject) => {
      db.get('SELECT S_ID FROM STUDENT WHERE U_ID = (SELECT U_ID FROM USER WHERE email = ?)', [studentEmail], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!student) {
      return res.status(404).send('Student not found');
    }

    // Get instructor ID based on instructor name
    const instructor = await new Promise((resolve, reject) => {
      db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID = (SELECT U_ID FROM USER WHERE name = ?)', [instructor_name], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!instructor) {
      return res.status(404).send('Instructor not found');
    }

    // Insert booking
    db.run(
      'INSERT INTO BOOKING (S_ID, I_ID, date, StartTime, EndTime) VALUES (?, ?, ?, ?, ?)',
      [student.S_ID, instructor.I_ID, date, startTime, endTime],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).send('Failed to create booking');
        }
        res.status(200).json({ message: 'Booking successful!', booking_id: this.lastID });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
module.exports = router;
