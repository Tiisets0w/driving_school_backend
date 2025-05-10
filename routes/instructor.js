const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const router = express.Router();
const db = new sqlite3.Database('db/database.db');

// Route to fetch all instructors
router.get('/', (req, res) => {
  db.all('SELECT name, surname, email FROM USER WHERE usertype = "instructor"', (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to fetch instructors' });
    }
    res.status(200).json(rows);
  });
});

// Route to fetch details of a specific instructor by name
router.get('/:name', (req, res) => {
  const instructorName = req.params.name;
  db.get(
    'SELECT U.*, I.* FROM USER U JOIN INSTRUCTOR I ON U.U_ID = I.U_ID WHERE U.usertype = "instructor" AND U.name = ?',
    [instructorName],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to fetch instructor details' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Instructor not found' });
      }
      res.status(200).json(row);
    }
  );
});

module.exports = router;
