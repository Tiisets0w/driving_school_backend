const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

// Mount routes
const instructorRoutes = require('./routes/instructor');
const bookingRoutes = require('./routes/booking');


const server = express();
const port = process.env.PORT || 3000;

server.use(cors());
server.use(express.json());

server.use(session({
  // name: 'connect.sid',	
  secret: '2022046a2d6c563e8af6b647ccdc2758c2f7b30d69744ed27fdccc65bf348f43',
  resave: false,
  saveUninitialized: true,
  //store: new SQLiteStore({ db: 'sessions.db', dir: './db' }),
  cookie: {
    path: '/',
    httpOnly: true,
    secure: false,  // 
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

const db = new sqlite3.Database("db/database.db");

server.get('/', (req, res) => {
  res.send('Welcome to the driving school API');
});

// Register Endpoint
server.post('/register', async (req, res) => {
  const { name, surname, email, password, user_type, dateofBirth, cellphoneNo, licenceNo, experience } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO USER (name, surname, email, password, usertype, datecreated) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [name, surname, email, hashedPassword, user_type],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).send('Failed to register user');
        }
        const user_id = this.lastID;
        if (user_type === 'student') {
          db.run(
            'INSERT INTO STUDENT(U_ID, dateofbirth, cellphoneNo) VALUES(?, ?, ?)',
            [user_id, dateofBirth, cellphoneNo],
            (err) => {
              if (err) {
                console.error(err);
                return res.status(500).send('Failed to register student profile');
              }
              req.session.user = {
                id: user_id,
                name,
                surname,
                email,
                usertype: 'student'
              };
              res.status(200).send('Student registered successfully');
            }
          );
        } else if (user_type === 'instructor') {
          db.run(
            'INSERT INTO INSTRUCTOR(U_ID, licenceNo, experience) VALUES(?, ?, ?)',
            [user_id, licenceNo, experience],
            (err) => {
              if (err) {
                console.error(err);
                return res.status(500).send('Failed to register instructor profile');
              }
              req.session.user = {
                id: user_id,
                name,
                surname,
                email,
                usertype: 'instructor'
              };
              res.status(200).send('Instructor registered successfully');
            }
          );
        } else {
          res.status(400).send('Invalid user type');
        }
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// Login Endpoint
server.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    db.get('SELECT * FROM USER WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      if (!row) {
        console.log('User not found for email:', email);
        return res.status(404).send('User not found');
      }
      const passwordMatch = await bcrypt.compare(password, row.password);
      if (!passwordMatch) {
        console.log('Incorrect password for email:', email);
        return res.status(401).send('Incorrect password');

      }
      req.session.user = {
        id: row.U_ID,
        email: row.email,
        name: row.name,
        surname: row.surname,
        usertype: row.usertype

      };
      console.log('Successful login. Session:', req.session.user);
      res.status(200).json(req.session.user)
      // res.status(200).json({ email: row.email, usertype: row.usertype });
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

// Logout Endpoint
server.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to logout');
    }
    res.clearCookie('connect.sid');
    res.status(200).send('Logged out successfully');
  });
});

// Get All Instructors
server.get('/instructors', (req, res) => {
  db.all('SELECT name, surname, email FROM USER WHERE usertype = "instructor"', (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch instructors');
    }
    res.status(200).json(rows);

  });
});

// Get Specific Instructor by Name
server.get('/instructors/:name', (req, res) => {
  const instructorName = req.params.name;
  console.log(`Fetching details for instructor: ${instructorName}`); 

  db.get(
    'SELECT U.*, I.* FROM USER U JOIN INSTRUCTOR I ON U.U_ID = I.U_ID WHERE U.usertype = "instructor" AND U.name = ?',
    [instructorName],

    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      if (!row) {
        console.log(`Instructor not found: ${instructorName}`);
        return res.status(404).send('Instructor not found :;');
      }
      console.log(`Instructor found: ${JSON.stringify(row)}`);
      res.status(200).json(row);
    }
  );
});




// Booking Endpoint
server.post('/booking', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }

  const { date, startTime, endTime, instructor_name, packageId, lessonId } = req.body; 
  const studentEmail = req.session.user.email;

  try {
    // Get student ID
    const student = await new Promise((resolve, reject) => {
      db.get('SELECT S_ID FROM STUDENT WHERE U_ID = (SELECT U_ID FROM USER WHERE email = ?)', [studentEmail], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!student) {
      return res.status(404).send('Student not found');
    }

    // Get instructor ID
    const instructor = await new Promise((resolve, reject) => {
      db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID = (SELECT U_ID FROM USER WHERE email = ?)', [instructor_name], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!instructor) {
      return res.status(404).send('Instructor not found');
    }

    // Insert booking
    db.run(
      'INSERT INTO BOOKING (S_ID, I_ID, P_ID, L_ID, date, StartTime, EndTime) VALUES (?, ?, ?, ?, ?, ?, ?)', // Added L_ID
      [student.S_ID, instructor.I_ID, packageId, lessonId, date, startTime, endTime],
      function (err) {
        if (err) {
          console.error('Error creating booking:', err);
          return res.status(500).send('Failed to create booking');
        }
        res.status(200).json({ message: 'Booking successful!', booking_id: this.lastID });
      }
    );
  } catch (error) {
    console.error('Internal Server Error:', error);
    res.status(500).send('Internal Server Error');
  }
});





// Get All Bookings
server.get('/bookings', (req, res) => {
  db.all('SELECT * FROM BOOKING', (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch bookings');
    }
    res.json(rows);
  });
});



server.get('/instructor-bookings', async (req, res) => {
  const userEmail = req.session.user && req.session.user.email;

  if (!userEmail) {
    return res.status(401).json({ error: 'Unauthorized: No user email found in session' });
  }

  try {
    // Fetch the instructor ID using the email from the session
    const instructorQuery = `
            SELECT I_ID 
            FROM INSTRUCTOR 
            WHERE U_ID = (SELECT U_ID FROM USER WHERE email = ?)
        `;
    const instructorResult = await new Promise((resolve, reject) => {
      db.get(instructorQuery, [userEmail], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!instructorResult || !instructorResult.I_ID) {
      return res.status(404).json({ error: 'Instructor not found' });
    }

    const instructorId = instructorResult.I_ID;

  


    const bookingsQuery = `
		
		SELECT 
    B.B_ID, B.L_ID, B.S_ID, B.I_ID, 
    B.date, B.StartTime as time, 
    U.name as student_name, U.surname as student_surname, 
    P.P_ID as package_id, P.name as package_name, 
    L.name as lesson_name
FROM 
    BOOKING B 
    JOIN STUDENT S ON B.S_ID = S.S_ID 
    JOIN USER U ON S.U_ID = U.U_ID 
    JOIN PACKAGES P ON B.P_ID = P.P_ID 
    JOIN LESSON L ON B.L_ID = L.L_ID 
WHERE 
    B.I_ID = ?`;


    const bookings = await new Promise((resolve, reject) => {
      db.all(bookingsQuery, [instructorId], (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });

    console.log('Bookings fetched:', bookings);
    res.status(200).json(bookings);
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});








// Function to fetch bookings from the database
const fetchBookingsFromDatabase = (email) => {
  return new Promise((resolve, reject) => {
    const sql = `
            SELECT 
                BOOKING.B_ID, 
                USER_STUDENT.name AS student_name, 
                USER_STUDENT.surname AS student_surname, 
                BOOKING.date, 
                BOOKING.StartTime AS time, 
                PACKAGES.name AS package_name,
                LESSON.name AS lesson_name
            FROM 
                BOOKING
            JOIN 
                INSTRUCTOR ON BOOKING.I_ID = INSTRUCTOR.I_ID
            JOIN 
                STUDENT ON BOOKING.S_ID = STUDENT.S_ID
            JOIN 
                USER AS USER_STUDENT ON STUDENT.U_ID = USER_STUDENT.U_ID
            JOIN 
                USER AS USER_INSTRUCTOR ON INSTRUCTOR.U_ID = USER_INSTRUCTOR.U_ID
            JOIN 
                PACKAGES ON BOOKING.P_ID = PACKAGES.P_ID
            JOIN 
                LESSON ON BOOKING.L_ID = LESSON.L_ID
            WHERE 
                USER_INSTRUCTOR.email = ?;
        `;
    db.all(sql, [email], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
};




///////////////Save Availability//////////////////////////////
server.post('/saveAvailability', (req, res) => {
  console.log('Session data:', req.session); 

  const { date, StartTime, EndTime } = req.body;
  const userId = req.session.user && req.session.user.id; 

  if (!userId) {
    return res.status(401).send('User not authenticated');
  }

  // Fetch I_ID based on the userId from the session
  const getInstructorIdQuery = 'SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?';

  db.get(getInstructorIdQuery, [userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.status(404).send('Instructor not found');
    }

    const { I_ID } = row;

    // Insert availability
    const insertQuery = 'INSERT INTO INSTRUCTORSAVAILABILITY (I_ID, date, StartTime, EndTime) VALUES (?, ?, ?, ?)';
    const values = [I_ID, date, StartTime, EndTime];

    db.run(insertQuery, values, function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      res.status(200).send('Availability saved successfully');
    });
  });
});

server.get('/availability/:instructorId', (req, res) => {
  console.log('Session:', req.session);
  const instructorId = req.params.instructorId;

  if (!instructorId) {
    return res.status(400).send('Instructor ID is required');
  }

  db.all('SELECT date, StartTime, EndTime FROM INSTRUCTORSAVAILABILITY WHERE I_ID = ?', [instructorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch availability');
    }
    res.status(200).json(rows);
  });
});


// Fetch instructor ID by email
server.get('/instructor/id/:email', (req, res) => {
  const email = req.params.email;

  if (!email) {
    return res.status(400).send('Email is required');
  }

  // Get the U_ID from USER table
  db.get('SELECT U_ID FROM USER WHERE email = ?', [email], (err, userRow) => {
    if (err) {
      console.error('Error fetching user ID:', err);
      return res.status(500).send('Failed to fetch user ID');
    }

    if (!userRow) {
      return res.status(404).send('User not found');
    }

    const userId = userRow.U_ID;

    // Get the I_ID from INSTRUCTOR table
    db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?', [userId], (err, instructorRow) => {
      if (err) {
        console.error('Error fetching instructor ID:', err);
        return res.status(500).send('Failed to fetch instructor ID');
      }

      if (!instructorRow) {
        return res.status(404).send('Instructor not found');
      }

      res.status(200).json({ I_ID: instructorRow.I_ID });
    });
  });
});






////////////////////
server.get('/getInstructorDetails', (req, res) => {
  if (!req.session.user || !req.session.user.email) {
    return res.status(400).json({ error: 'No user or user email found' });
  }

  const instructorEmail = req.session.user.email;

  db.all('SELECT * FROM USER WHERE email = ?', [instructorEmail], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }
    if (!rows.length) {
      return res.status(404).send('Instructor not found');
    }
    res.status(200).json(rows);
  });
});
//Select packages endpoint
server.post('/select-package', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }

  const { packageId } = req.body;
  if (!packageId) {
    console.error('Package ID is missing in request body');
    return res.status(400).send('Package ID is required');
  }
  console.log('Received packageId:', packageId);
  req.session.packageId = packageId;
  res.status(200).send('Package selected');
});

///Packages endpoint
server.get('/packages', (req, res) => {
  db.all('SELECT * FROM PACKAGES', (err, rows) => {
    if (err) {
      console.error('Error fetching packages:', err);
      return res.status(500).send('Internal Server Error');
    }
    res.status(200).json(rows);
  });
});


server.post('/alerts', (req, res) => {
  const { message } = req.body;
  const U_ID = req.session.user && req.session.user.id; 

  if (!U_ID) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  const sql = 'INSERT INTO ALERTS (message, U_ID) VALUES (?, ?)';
  db.run(sql, [message, U_ID], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ A_ID: this.lastID });
  });
});

/////Alerts get///////////////////////
server.get('/alerts', (req, res) => {
  const U_ID = req.session.user && req.session.user.id; 

  if (!U_ID) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  const sql = 'SELECT * FROM ALERTS WHERE U_ID = ?';
  db.all(sql, [U_ID], (err, rows) => {
    if (err) {
      console.error('Error fetching alerts:', err.message);
      return res.status(500).json({ error: err.message });
    }

    if (rows.length === 0) {
      return res.status(404).json({ message: 'No alerts found for this user' });
    }

    res.json(rows);
  });
});

//////////////////HELPER FUNCTIONS/////////////////////////////////////
const getBookingById = (bookingId) => {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM BOOKING WHERE B_ID = ?', [bookingId], (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
};

// Get instructor email by ID
const getInstructorEmailById = (iId) => {
  return new Promise((resolve, reject) => {
    db.get('SELECT email FROM USER INNER JOIN INSTRUCTOR ON USER.U_ID = INSTRUCTOR.U_ID WHERE INSTRUCTOR.I_ID = ?', [iId], (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
};

// Get package details by ID
const getPackageDetailsById = (pId) => {
  return new Promise((resolve, reject) => {
    db.get('SELECT name FROM PACKAGES WHERE P_ID = ?', [pId], (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
};

// Delete booking by ID
const deleteBookingById = (bookingId) => {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM BOOKING WHERE B_ID = ?', [bookingId], function (err) {
      if (err) {
        reject(err);
      } else {
        resolve(this.changes);
      }
    });
  });
};

// Create alert
const createAlert = (userId, message) => {
  return new Promise((resolve, reject) => {
    db.run('INSERT INTO ALERTS (U_ID, message) VALUES (?, ?)', [userId, message], function (err) {
      if (err) {
        reject(err);
      } else {
        resolve(this.lastID);
      }
    });
  });
};




///////////DELETING BOOKING ENDPOINT////////////////////////////////

server.delete('/booking/:id', async (req, res) => {
  const bookingId = req.params.id;

  try {
    // Fetch the booking details
    const booking = await getBookingById(bookingId);
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    
    const studentUIdQuery = `
            SELECT USER.U_ID
            FROM STUDENT
            INNER JOIN USER ON STUDENT.U_ID = USER.U_ID
            WHERE STUDENT.S_ID = ?
        `;
    const studentUIdRow = await new Promise((resolve, reject) => {
      db.get(studentUIdQuery, [booking.S_ID], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (!studentUIdRow) {
      return res.status(404).json({ message: 'Student not found' });
    }

    const studentUId = studentUIdRow.U_ID;

    // Fetch the instructor's name using I_ID from the booking
    const instructorNameQuery = `
            SELECT USER.name
            FROM INSTRUCTOR
            INNER JOIN USER ON INSTRUCTOR.U_ID = USER.U_ID
            WHERE INSTRUCTOR.I_ID = ?
        `;
    const instructorNameRow = await new Promise((resolve, reject) => {
      db.get(instructorNameQuery, [booking.I_ID], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (!instructorNameRow) {
      return res.status(404).json({ message: 'Instructor not found' });
    }

    const instructorName = instructorNameRow.name;

    
    const packageDetailsQuery = `
            SELECT name
            FROM PACKAGES
            WHERE P_ID = ?
        `;
    const packageDetailsRow = await new Promise((resolve, reject) => {
      db.get(packageDetailsQuery, [booking.P_ID], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (!packageDetailsRow) {
      return res.status(404).json({ message: 'Package not found' });
    }

    const packageName = packageDetailsRow.name;

    // Delete the booking
    await deleteBookingById(bookingId);

    // Creating an alert for the student
    const alertMessage = `Your booking with instructor ${instructorName} on ${booking.date} from ${booking.StartTime} to ${booking.EndTime} for ${packageName} has been cancelled.`;
    await createAlert(studentUId, alertMessage);

    res.status(200).json({ message: 'Booking deleted successfully' });
  } catch (error) {
    console.error('Error deleting booking:', error);
    res.status(500).json({ message: 'Failed to delete booking' });
  }
});


//////////////Scoring///////////////////////////////////////////
// Fetch student's scores
server.get('/student-marks/:studentId', async (req, res) => {
  const studentId = req.params.studentId;

  try {
    // Querying the Score table
    const scoreQuery = `
            SELECT *
            FROM Score
            WHERE S_ID = ?
        `;
    const scores = await new Promise((resolve, reject) => {
      db.all(scoreQuery, [studentId], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });

  
    const results = {};
    for (const score of scores) {
      const tableName = score.nameCourse;
      const tableQuery = `
                SELECT *
                FROM ${tableName}
                WHERE Sc_ID = ?
            `;
      const tableData = await new Promise((resolve, reject) => {
        db.get(tableQuery, [score.Sc_ID], (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        });
      });
      results[tableName] = tableData;
    }

    res.json(results);
  } catch (error) {
    console.error('Error fetching student marks:', error);
    res.status(500).json({ message: 'Failed to fetch student marks' });
  }
});






server.post('/store-scores', async (req, res) => {
  // Check if user is authenticated
  if (!req.session.user) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { S_ID, I_ID, nameCourse, scores, L_ID, P_ID } = req.body;
  console.log('Incoming request body:', req.body);

  // Check for missing fields
  if (!S_ID || !I_ID || !nameCourse || !scores || !L_ID || !P_ID) {
    const missingFields = [];
    if (!S_ID) missingFields.push('S_ID');
    if (!I_ID) missingFields.push('I_ID');
    if (!nameCourse) missingFields.push('nameCourse');
    if (!scores) missingFields.push('scores');
    if (!L_ID) missingFields.push('L_ID');
    if (!P_ID) missingFields.push('P_ID');

    console.error('Missing fields:', missingFields);
    return res.status(400).json({ error: 'Missing required fields', missingFields });
  }

  
  const parsedS_ID = parseInt(S_ID, 10);
  const parsedI_ID = parseInt(I_ID, 10);
  const parsedL_ID = parseInt(L_ID, 10);
  const parsedP_ID = parseInt(P_ID, 10);


  // Defining the criteria mapping for each course
  const criteriaMapping = {
    Assessment: {
      "Clutch/Gear Control": 1,
      "Steady steering wheel": 2,
      "Moving off": 3,
      "Changing lanes": 4,
      "Speed control": 5
    },
    AlleyDocking: {
      "Move left": 6,
      "Move right": 7
    },
    InclineStart: {
      "Brake control": 8,
      "Prevent from rolling back": 9
    },
    Parking: {
      "wheel alignment": 10,
      "line observation": 11,
      "check mirrors": 12,
      "steering wheel control": 13
    }
  };

  // Check if the provided nameCourse is valid
  if (!criteriaMapping[nameCourse]) {
    console.error('Lesson not recognized or not available:', nameCourse);
    return res.status(400).json({ error: 'Lesson not recognized or not available' });
  }

  // Validate if all score fields are provided
  const missingScoreKeys = Object.keys(criteriaMapping[nameCourse]).filter(key => scores[key] === undefined);
  if (missingScoreKeys.length > 0) {
    console.error('Missing score fields:', missingScoreKeys);
    return res.status(400).json({ error: 'Missing score fields', missingScoreKeys });
  }

  // Parse the scores and validate
  const parsedScores = {};
  for (const [criterion, score] of Object.entries(scores)) {
    const parsedScore = parseInt(score, 10);
    if (isNaN(parsedScore) || parsedScore < 0 || parsedScore > 100) {  
      console.error(`Invalid score for ${criterion}: ${score}`);
      return res.status(400).json({ error: `Invalid score for ${criterion}: ${score}` });
    }
    parsedScores[criterion] = parsedScore;
  }

  
  try {
    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');

        let insertCount = 0;
        let errorOccurred = false;

        Object.entries(criteriaMapping[nameCourse]).forEach(([criterion, CR_ID]) => {
          const MARK = parsedScores[criterion];
          db.run(
            `INSERT INTO MARKS (S_ID, L_ID, CR_ID, MARK) VALUES (?, ?, ?, ?)`,
            [S_ID, L_ID, CR_ID, MARK],
            function (err) {
              if (err) {
                errorOccurred = true;
                db.run('ROLLBACK');
                console.error('Error inserting mark:', err);
                return reject(err);
              }
              insertCount++;
            }
          );
        });

        if (!errorOccurred) {
          db.run('COMMIT', (err) => {
            if (err) {
              console.error('Error committing transaction:', err);
              return reject(err);
            }
            resolve();
          });
        }
      });
    });

    res.status(200).json({ message: 'Scores saved successfully' });
  } catch (error) {
    console.error('Error saving scores:', error);
    res.status(500).json({ error: 'Failed to save scores' });
  }
});

////////////////////////////////////////////////////////////////////////////////////

async function fetchCriteriaFromDatabase(L_ID) {
  return new Promise((resolve, reject) => {
    const query = 'SELECT CR_Name FROM CRITERIA WHERE L_ID = ?';
    db.all(query, [L_ID], (error, rows) => {
      if (error) {
        console.error('Database query error:', error);
        return reject(error);
      }

      if (rows.length === 0) {
        return resolve(null); //If criteria is not found
      }

      resolve(rows); // Returning the fetched criteria
    });
  });
}

// GET /get-criteria endpoint
server.get('/get-criteria', async (req, res) => {
  try {
    const { L_ID } = req.query;

   
    if (!L_ID) {
      return res.status(400).json({ error: 'L_ID parameter is required' });
    }

    // Fetch criteria from the database
    const criteria = await fetchCriteriaFromDatabase(L_ID);

    
    if (!criteria) {
      return res.status(404).json({ error: 'No criteria found for the provided L_ID' });
    }

    
    res.json(criteria);
  } catch (error) {
    
    console.error('Internal Server Error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});







server.get('/scores', async (req, res) => {
  const { S_ID, L_ID } = req.query;

  if (!S_ID || !L_ID) {
    console.log('Missing S_ID or L_ID');
    return res.status(400).json({ error: 'S_ID and L_ID are required' });
  }

  console.log('Fetching scores for S_ID:', S_ID, 'L_ID:', L_ID);
  try {
    // Query to fetch scores and criterias names
    const query = `
            SELECT 
                CR.CR_Name,
                M.MARK
            FROM MARKS M
            JOIN CRITERIA CR ON M.CR_ID = CR.CR_ID
            WHERE M.S_ID = ? AND M.L_ID = ?
        `;

    const scores = await new Promise((resolve, reject) => {
      db.all(query, [S_ID, L_ID], (err, rows) => {
        if (err) {
          console.error('Database error:', err.message);
          return reject(err);
        }
        if (!rows.length) {
          console.log('No data found for given S_ID and L_ID');
          return resolve([]);
        }
        console.log('Database rows:', rows);
        resolve(rows);
      });
    });

    if (!scores.length) {
      console.log(`No scores found for S_ID: ${S_ID}, L_ID: ${L_ID}`);
      return res.status(404).json({ error: 'Scores not found' });
    }

    
    const formattedScores = scores.reduce((acc, row) => {
      acc[row.CR_Name] = row.MARK;
      return acc;
    }, {});

    console.log('Scores fetched successfully:', formattedScores);
    res.status(200).json(formattedScores);
  } catch (error) {
    console.error('Error retrieving scores:', error);
    res.status(500).json({ error: 'Failed to retrieve scores' });
  }
});




///////////////////////Fetching from score table/////////////////////////////////
server.get('/scoreResults', async (req, res) => {
  const { S_ID, L_ID } = req.query;

  if (!S_ID || !L_ID) {
    return res.status(400).json({ error: 'S_ID and L_ID are required' });
  }

  try {
    const scores = await new Promise((resolve, reject) => {
      db.all(`
                SELECT SC_ID, Mark, date
                FROM SCORE
                WHERE S_ID = ? AND L_ID = ?
                ORDER BY date ASC
            `, [S_ID, L_ID], (err, rows) => {
        if (err) {
          return reject(err);
        }
        if (!rows || rows.length === 0) {
          return resolve(null);
        }
        resolve(rows);
      });
    });

    if (!scores) {
      return res.status(404).json({ error: 'Scores not found' });
    }

    res.status(200).json(scores);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve scores' });
  }
});





// Endpoint to get student ID by email
server.get('/student-id-by-email', (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).send('Email is required');
  }

  // Query to get U_ID from User table
  db.get('SELECT U_ID FROM USER WHERE email = ?', [email], (err, userRow) => {
    if (err) {
      console.error('Error fetching user ID:', err);
      return res.status(500).send('Failed to fetch user ID');
    }

    if (!userRow) {
      return res.status(404).send('User not found');
    }

    const userId = userRow.U_ID;

    // Query to get S_ID from Student table
    db.get('SELECT S_ID FROM STUDENT WHERE U_ID = ?', [userId], (err, studentRow) => {
      if (err) {
        console.error('Error fetching student ID:', err);
        return res.status(500).send('Failed to fetch student ID');
      }

      if (!studentRow) {
        return res.status(404).send('Student not found');
      }

      res.status(200).json({ S_ID: studentRow.S_ID });
    });
  });
});




///////// Fetch specific student details by student ID
server.get('/student/:email', (req, res) => {
  const studentEmail = req.params.email;

  db.get(
    `SELECT U.*, S.S_ID
     FROM USER U
     JOIN STUDENT S ON U.U_ID = S.U_ID
     WHERE U.email = ?;`,
    [studentEmail],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      if (!row) {
        return res.status(404).send('Student not found');
      }
      res.status(200).json(row);
    }
  );
});

/////////////////Fetching student ID////////////////////////

server.get('/student/id/:name/:surname', (req, res) => {
  const { name, surname } = req.params;

  console.log(`Received name: ${name}, surname: ${surname}`); 

  if (!name || !surname) {
    return res.status(400).send('Name and surname are required');
  }

  // Query to get the student ID from USER and STUDENT tables
  const query = `
    SELECT STUDENT.S_ID 
    FROM STUDENT 
    JOIN USER ON STUDENT.U_ID = USER.U_ID 
    WHERE USER.name = ? AND USER.surname = ?
  `;

  db.get(query, [name, surname], (err, row) => {
    if (err) {
      console.error('Error fetching student ID:', err);
      return res.status(500).send('Failed to fetch student ID');
    }

    if (!row) {
      console.log('No student found with the given name and surname'); 
      return res.status(404).send('Student not found');
    }

    res.status(200).json({ S_ID: row.S_ID });
  });
});


server.get('/lesson/name/:name', (req, res) => {
  if (!req.session.user) {
    console.error('Unauthorized access attempt.');
    return res.status(401).send('Unauthorized');
  }

  const lessonName = req.params.name;

  console.log(`Fetching lesson ID for lesson name: ${lessonName}`);

  db.get('SELECT L_ID FROM LESSON WHERE name = ?', [lessonName], (err, row) => {
    if (err) {
      console.error('Error fetching lesson ID:', err);
      return res.status(500).send('Failed to fetch lesson ID');
    }

    if (!row) {
      console.error(`Lesson not found for name: ${lessonName}`);
      return res.status(404).send('Lesson not found');
    }

    console.log(`Lesson ID for ${lessonName}: ${row.L_ID}`);
    res.status(200).json({ L_ID: row.L_ID });
  });
});





//////////////////////CONFIRM BOOKING/////////////////////////////////
/*const getBookingById = (bookingId) => {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM BOOKING WHERE B_ID = ?', [bookingId], (err, row) => {
            if (err) {
                return reject(err);
            }
            resolve(row);
        });
    });
};*/

const confirmBookingById = (bookingId) => {
  return new Promise((resolve, reject) => {
    db.run('UPDATE BOOKING SET status = ? WHERE B_ID = ?', ['confirmed', bookingId], (err) => {
      if (err) {
        return reject(err);
      }
      resolve();
    });
  });
};

/*const createAlert = (userId, message) => {
    return new Promise((resolve, reject) => {
        db.run('INSERT INTO ALERTS (message, U_ID) VALUES (?, ?)', [message, userId], (err) => {
            if (err) {
                return reject(err);
            }
            resolve();
        });
    });
};*/

// Confirm Booking Endpoint
server.post('/confirm-booking/:id', async (req, res) => {
  const bookingId = req.params.id;

  try {
    // Fetch the booking details
    const booking = await getBookingById(bookingId);
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    // Fetch the student's U_ID using S_ID from the booking
    const studentUIdQuery = `
            SELECT USER.U_ID
            FROM STUDENT
            INNER JOIN USER ON STUDENT.U_ID = USER.U_ID
            WHERE STUDENT.S_ID = ?
        `;
    const studentUIdRow = await new Promise((resolve, reject) => {
      db.get(studentUIdQuery, [booking.S_ID], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (!studentUIdRow) {
      return res.status(404).json({ message: 'Student not found' });
    }

    const studentUId = studentUIdRow.U_ID;

    // Fetch the instructor's name and surname using I_ID from the booking
    const instructorNameQuery = `
            SELECT USER.name, USER.surname
            FROM INSTRUCTOR
            INNER JOIN USER ON INSTRUCTOR.U_ID = USER.U_ID
            WHERE INSTRUCTOR.I_ID = ?
        `;
    const instructorNameRow = await new Promise((resolve, reject) => {
      db.get(instructorNameQuery, [booking.I_ID], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (!instructorNameRow) {
      return res.status(404).json({ message: 'Instructor not found' });
    }

    const instructorName = instructorNameRow.name;
    const instructorSurname = instructorNameRow.surname;

    
    const packageDetailsQuery = `
            SELECT name
            FROM PACKAGES
            WHERE P_ID = ?
        `;
    const packageDetailsRow = await new Promise((resolve, reject) => {
      db.get(packageDetailsQuery, [booking.P_ID], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (!packageDetailsRow) {
      return res.status(404).json({ message: 'Package not found' });
    }

    const packageName = packageDetailsRow.name;

    // Create an alert for the student
    const alertMessage = `Your booking with instructor ${instructorName} ${instructorSurname} on ${booking.date} from ${booking.StartTime} to ${booking.EndTime} for ${packageName} has been confirmed.`;
    await createAlert(studentUId, alertMessage);

    res.status(200).json({ message: 'Booking confirmed successfully' });
  } catch (error) {
    console.error('Error confirming booking:', error);
    res.status(500).json({ message: 'Failed to confirm booking' });
  }
});

//////////////////Progress////////////////////////////////////

server.post('/store-progress', async (req, res) => {
  const { S_ID, L_ID, OVERALL_SCORE, STATUS, I_ID } = req.body;

  if (!S_ID || !L_ID || !OVERALL_SCORE || !STATUS || !I_ID) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
   
    const query = `
            INSERT INTO PROGRESS (S_ID, L_ID, I_ID, OVERALL_SCORE, STATUS, datecreated)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;

    const result = await db.run(query, [S_ID, L_ID, I_ID, OVERALL_SCORE, STATUS]);

    if (result) {
      res.status(200).json({ message: 'Progress saved successfully' });
    } else {
      res.status(500).json({ error: 'Failed to save progress' });
    }
  } catch (error) {
    console.error('Error inserting progress:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

////Submit ratings////////////////////////////

/*server.post('/submit-rating', async (req, res) => {
    const { S_ID, I_ID, Rating, Comment } = req.body;

    // Validate input
    if (!S_ID || !I_ID || !Rating || Rating < 1 || Rating > 5) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    try {
        // Insert the new rating into the RATINGS table
        const query = `
            INSERT INTO RATINGS (S_ID, I_ID, Rating, Comment)
            VALUES (?, ?, ?, ?)
        `;

        await db.run(query, [S_ID, I_ID, Rating, Comment]);

        res.status(201).json({ message: 'Rating submitted successfully' });
    } catch (error) {
        console.error('Error submitting rating:', error);
        res.status(500).json({ error: 'Failed to submit rating' });
    }
})*/

///Fetch Instructor
server.get('/instructor-ratings', async (req, res) => {
  const { S_ID } = req.query;

  if (!S_ID) {
    return res.status(400).json({ error: 'S_ID is required' });
  }

  try {
    const query = `
            SELECT 
                I.I_ID,
                U.name AS instructor_name,
                U.surname AS instructor_surname,
                L.lesson_name,
                P.STATUS
            FROM 
                PROGRESS P
            JOIN 
                LESSON L ON P.L_ID = L.L_ID
            JOIN 
                INSTRUCTOR I ON P.I_ID = I.I_ID
            JOIN 
                USER U ON I.U_ID = U.U_ID
            WHERE 
                P.S_ID = ?`;

    const [rows] = await db.execute(query, [S_ID]);

    res.json(rows);
  } catch (error) {
    console.error('Error fetching instructor ratings:', error);
    res.status(500).json({ error: 'Failed to fetch instructor ratings' });
  }
});





server.get('/fetch-instructors-and-lessons', async (req, res) => {
  
  const S_ID = req.query.S_ID || req.session.studentId;

  if (!S_ID) {
    return res.status(400).json({ error: 'Student ID is required' });
  }

  console.log('Fetching instructors and lessons for S_ID:', S_ID);

  try {
    const sqlQuery = `
            SELECT DISTINCT I.I_ID, U.name AS instructor_name, L.L_ID, L.name AS lesson_name
            FROM PROGRESS P
            JOIN INSTRUCTOR I ON I.I_ID = P.I_ID
            JOIN LESSON L ON P.L_ID = L.L_ID
            JOIN USER U ON I.U_ID = U.U_ID
            WHERE P.S_ID = ?
        `;

    console.log('SQL Query:', sqlQuery);
    const instructors = await new Promise((resolve, reject) => {
      db.all(sqlQuery, [S_ID], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });

    console.log('Fetched instructors and lessons:', instructors);

    if (instructors.length === 0) {
      console.warn('No instructors or lessons found for Student ID:', S_ID);
      return res.status(404).json({
        message: 'No instructors or lessons found for this student',
        S_ID: S_ID
      });
    }

    return res.json(instructors);
  } catch (error) {
    console.error('Error fetching instructors and lessons:', error);

    return res.status(500).json({
      error: 'Internal Server Error',
      details: error.message
    });
  }
});



server.get('/get-student-id-from-session', (req, res) => {
  if (req.session.user && req.session.user.id) {
    const U_ID = req.session.user.id;

    
    const query = 'SELECT S_ID FROM STUDENT WHERE U_ID = ?';
    db.get(query, [U_ID], (err, row) => {
      if (err) {
        console.error('Error fetching student ID:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Student ID not found for this user' });
      }

      
      res.json({ S_ID: row.S_ID });
    });
  } else {
    return res.status(400).json({ error: 'User ID is not available in session' });
  }
});


server.get('/get-instructor-id-from-session', (req, res) => {
    if (req.session.user && req.session.user.id) {
        const U_ID = req.session.user.id;

        // Fetch I_ID according to the U_ID
        const query = 'SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?';
        db.get(query, [U_ID], (err, row) => {
            if (err) {
                console.error('Error fetching instructor ID:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            if (!row) {
                return res.status(404).json({ error: 'Instructor ID not found for this user' });
            }

           
            res.json({ I_ID: row.I_ID });
        });
    } else {
        return res.status(400).json({ error: 'User ID is not available in session' });
    }
});


server.get('/students-by-instructor', async (req, res) => {
    const instructorId = req.query.I_ID; 

    
    console.log('Instructor ID from query:', instructorId);

    if (!instructorId) {
        return res.status(401).json({ message: "Unauthorized: No instructor ID provided" });
    }

    try {
        const query = `
            SELECT S.S_ID, U.name 
            FROM BOOKING B
            JOIN STUDENT S ON B.S_ID = S.S_ID
            JOIN USER U ON S.U_ID = U.U_ID
            WHERE B.I_ID = ?
        `;
        
        const students = await new Promise((resolve, reject) => {
            db.all(query, [instructorId], (err, rows) => {
                if (err) {
                    return reject(err);
                }
                resolve(rows);
            });
        });

       
        if (students.length === 0) {
            return res.status(404).json({ message: 'No students found for this instructor' });
        }

        // Responding with the list of students
        res.json(students);
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({ message: 'Error fetching students', error });
    }
});







server.post('/submit-rating', async (req, res) => {
    
    console.log('Received request at /submit-rating endpoint');
    console.log('Request body:', req.body);

    const { I_ID, S_ID, L_ID, rating, comment } = req.body;

    
    console.log('Instructor ID:', I_ID);
    console.log('Student ID:', S_ID);
    console.log('Lesson ID:', L_ID);
    console.log('Rating:', rating);
    console.log('Comment:', comment);

   
    if (!I_ID || !S_ID || !L_ID || !rating) {
        console.error('Missing required fields');
        return res.status(400).json({ error: 'Instructor ID, Student ID, Lesson ID, and rating are required' });
    }

    
    if (rating < 1 || rating > 5) {
        console.error('Rating must be between 1 and 5');
        return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    try {
       
        console.log('Preparing to execute SQL query');

        const sqlQuery = `
            INSERT INTO RATINGS (I_ID, S_ID, L_ID, rating, comment, datecreated)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;
        await db.run(sqlQuery, [I_ID, S_ID, L_ID, rating, comment || '']);

        
        console.log('Rating successfully submitted');

        return res.status(200).json({ message: 'Rating submitted successfully' });
    } catch (error) {
        
        console.error('Error submitting rating:', error.message);

        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

/////////Chatting///
server.get('/fetchMessages', (req, res) => {
    const studentId = req.query.S_ID;
    const instructorId = req.query.I_ID;

    const query = `
        SELECT * FROM ChatMessages
        WHERE S_ID = ? AND I_ID = ?
        ORDER BY timestamp ASC
    `;

    db.all(query, [studentId, instructorId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

/////sending message
server.post('/send-message', async (req, res) => {
    const { S_ID, I_ID, message, senderType } = req.body;

    
    console.log('Received message data:', { S_ID, I_ID, message, senderType });

    
    if (!S_ID || !I_ID || !message || !senderType) {
        return res.status(400).json({ message: 'Bad Request: Missing required fields' });
    }

    try {
        
        await db.run(` 
            INSERT INTO ChatMessages (S_ID, I_ID, message, senderType, timestamp)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        `, [S_ID, I_ID, message, senderType]);

        res.json({ message: 'Message sent successfully' });
    } catch (error) {
        console.error('Error sending message:', error); 
        res.status(500).json({ message: 'Error sending message', error });
    }
});

server.get('/instructors-by-student', async (req, res) => {
    const studentId = req.query.S_ID; 

    
    console.log('Student ID from query:', studentId);

    if (!studentId) {
        return res.status(401).json({ message: "Unauthorized: No student ID provided" });
    }

    try {
        const query = `
            SELECT I.I_ID, U.name 
            FROM BOOKING B
            JOIN INSTRUCTOR I ON B.I_ID = I.I_ID
            JOIN USER U ON I.U_ID = U.U_ID
            WHERE B.S_ID = ?
        `;
        
        const instructors = await new Promise((resolve, reject) => {
            db.all(query, [studentId], (err, rows) => {
                if (err) {
                    return reject(err);
                }
                resolve(rows);
            });
        });

        
        if (instructors.length === 0) {
            return res.status(404).json({ message: 'No instructors found for this student' });
        }

        // Respond with the list of instructors
        res.json(instructors);
    } catch (error) {
        console.error('Error fetching instructors:', error);
        res.status(500).json({ message: 'Error fetching instructors', error });
    }
});


server.get('/chat-history', (req, res) => {
  const { S_ID, I_ID } = req.query;

  console.log('Request Query:', req.query);
  console.log('Received S_ID:', S_ID, 'Received I_ID:', I_ID);

  // Validate input
  if (!S_ID || !I_ID) {
    console.log('Bad Request: Missing S_ID or I_ID');
    return res.status(400).json({ message: 'Bad Request: Missing S_ID or I_ID' });
  }

  const intS_ID = parseInt(S_ID, 10);
  const intI_ID = parseInt(I_ID, 10);

  console.log('Parsed S_ID:', intS_ID, 'Parsed I_ID:', intI_ID);

  const sqlQuery = `
    SELECT message, senderType, timestamp 
    FROM ChatMessages 
    WHERE S_ID = ? AND I_ID = ? 
    ORDER BY timestamp ASC`;

  
  db.all(sqlQuery, [intS_ID, intI_ID], (err, messages) => {
    if (err) {
      console.error('Error running SQL query:', err.message);
      return res.status(500).json({ message: 'Error fetching chat history', error: err });
    }

    console.log('Executed SQL query, messages:', messages);

   
    if (messages.length === 0) {
      console.log('No messages found for S_ID:', intS_ID, 'and I_ID:', intI_ID);
      return res.json([]); 
    }

    // Return the fetched messages
    res.json(messages);
  });
});






//////////////////////////////WEB/////////////////////////////////////////








//////////////////////////////////////////////////////////END POINT FOR PURCHASING A LESSON LINK THEM TO THEIR PURCHASES //////////////////////////////////////////////////////////
function getStudentIdByUserId(userId) {
  return new Promise((resolve, reject) => {
    db.get('SELECT S_ID FROM STUDENT WHERE U_ID = ?', [userId], (err, student) => {
      if (err) {
        return reject(err);
      }
      resolve(student ? student.S_ID : null);
    });
  });
}

//GETTING THE STUDENT PACKAGE FROM THE USER
server.post('/get-student-package/:storedUserId', async (req, res) => {
  const user_id = req.params.storedUserId;
  console.log('LOOOVE' + user_id);

  if (!user_id) {
    return res.status(400).send('Require user ID');
  }

  try {
    const studentID = await getStudentIdByUserId(user_id);
    console.log('YOOUUU' + studentID);

    //getting the package Id for the specific student
    db.get('SELECT P_ID FROM STUDENT_PACKAGE WHERE S_ID=?', [studentID], (err, PackageRow) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Failed to fetch the package');
      }

      if (!PackageRow) {
        return res.status(404).send('No package found for the specified student');
      }


      res.status(200).json({ packageId: PackageRow.P_ID });



    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Database error');
  }

});

server.get('/getpackages', (req, res) => {
  const databaseQuery = `
    SELECT 
      PACKAGES.P_ID, 
      PACKAGES.name AS packageName, 
      PACKAGES.noLessons, 
      PACKAGES.price, 
      CODENUMBER.code, 
      LESSON.name AS lessonName
    FROM 
      PACKAGES 
      JOIN CODE_PACKAGE ON PACKAGES.P_ID = CODE_PACKAGE.P_ID
      JOIN CODENUMBER ON CODE_PACKAGE.Code_ID = CODENUMBER.Code_ID
      JOIN PACKAGE_LESSON ON PACKAGES.P_ID = PACKAGE_LESSON.P_ID
      JOIN LESSON ON PACKAGE_LESSON.L_ID = LESSON.L_ID
    ORDER BY PACKAGES.P_ID, LESSON.name`;

  try {
    db.all(databaseQuery, [], (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send('server failed to respond');
        return;
      }

      const packages = {};

      rows.forEach(row => {
        const { P_ID, packageName, noLessons, price, code, lessonName } = row;

        if (!packages[code]) {
          packages[code] = [];
        }

        const existingPackage = packages[code].find(pkg => pkg.P_ID === P_ID);
        if (existingPackage) {
          existingPackage.lessons.push(lessonName);
        } else {
          packages[code].push({
            P_ID,
            name: packageName,
            noLessons,
            price,
            lessons: [lessonName]
          });
        }

      });


      res.json(packages);
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//this get the pakage the student booked for also left joins the students booking to get the time and date they booked for 
server.get('/get-student-lessons/:userId', (req, res) => {
  const userId = req.params.userId;
  console.log(userId);

  db.get('SELECT S_ID FROM STUDENT WHERE U_ID = ?', [userId], (err, student) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Could not get the student ID');
    }
    //checks if the student exists
    if (student) {
      const studentId = student.S_ID;
      console.log(studentId);

      const query = `
        SELECT 
          STUDENT_PACKAGE.remaining_lessons,
          PACKAGES.P_ID AS packageId,
          PACKAGES.name AS packageName,
          LESSON.name AS lessonName,
          LESSON.L_ID AS lessonId,
          BOOKING.date AS dateBooked ,
          BOOKING.StartTime as startTime,
          BOOKING.EndTime as endTime 
        FROM 
          STUDENT_PACKAGE 
          JOIN PACKAGES  ON STUDENT_PACKAGE.P_ID = PACKAGES.P_ID
          JOIN PACKAGE_LESSON  ON PACKAGES.P_ID = PACKAGE_LESSON.P_ID
          JOIN LESSON  ON PACKAGE_LESSON.L_ID = LESSON.L_ID
          LEFT JOIN BOOKING ON LESSON.L_ID = BOOKING.L_ID AND STUDENT_PACKAGE.S_ID= BOOKING.S_ID
        WHERE 
          STUDENT_PACKAGE.S_ID = ?
        ORDER BY PACKAGES.P_ID, LESSON.L_ID`;
      //
      db.all(query, [studentId], (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Could not fetch students  lessons from the server');
        }

        if (rows.length === 0) {
          return res.status(404).send(' Student did not purchase the any lessons');
        }



        //calculate the number of the lessons booked by a student 
        const bookedLessonsQuery = `
          SELECT 
            PACKAGES.P_ID AS packageId,
            COUNT( BOOKING.L_ID) AS bookedLessons
          FROM 
            BOOKING
            JOIN PACKAGES ON BOOKING.P_ID = PACKAGES.P_ID
          WHERE 
            BOOKING.S_ID = ?
          GROUP BY PACKAGES.P_ID`;


        db.all(bookedLessonsQuery, [studentId], (err, bookedRows) => {
          if (err) {
            console.error(err);
            return res.status(500).send('Could not fetch booked lessons');
          }

          // Create a map to store booked lessons count per package
          const bookedLessonsMap = new Map();
          bookedRows.forEach(row => {
            bookedLessonsMap.set(row.packageId, row.bookedLessons);
          });
          // });



          const lessons = {};

          rows.forEach(row => {
            const { packageId, packageName, lessonName, remaining_lessons, lessonId, dateBooked, startTime, endTime } = row;

            if (!lessons[packageName]) {
              lessons[packageName] = {
                remaining_lessons,
                lessons: []
              };
            }
            // Get the number of booked lessons for this package
            const bookedLessonsCount = bookedLessonsMap.get(packageId) || 0;
            // const currentRemainingLessons = remaining_lessons - bookedLessonsCount;
            lessons[packageName].lessons.push({
              packageId,
              lessonName,
              lessonId,
              dateBooked,
              startTime,
              endTime,
              //  remainingLessons: currentRemainingLessons
            });
          });
          console.log('Lessons data:', lessons);
          res.json(lessons);
        });
      });
    } else {
      res.status(404).send('Student is not registerd');
    }
  });
});


//END POINT FOR SAVING THE INSTRUCTORS AVAILABILITY FROM INSTRUCTOR SIDES 

server.post('/saveInstructorsAvailability', async (req, res) => {

  const { userId, userType, date, startTime, endTime } = req.body;
  console.log(req.body);

  //checking if the users is authorised 
  if (!userId || !userType == 'instructor') {
    return res.status(401).send('Unauthorised');
  }
  console.log('hello');
  //getting the instructor Id using the user ID stored in the session
  try {
    db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID=?', [userId], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Could not get instructors ID');
      }
      if (!row) {
        return res.status(404).send('Instructor is not registered');
      }
      console.log('hello');
      const instructorId = row.I_ID;
      console.log(instructorId);
      db.run('INSERT INTO INSTRUCTORSAVAILABILITY(I_ID,date,StartTime,EndTime)VALUES(?,?,?,?)',
        [instructorId, date, startTime, endTime],

        function (err) {
          if (err) {
            console.error(err);
            return res.status(500).send('Failed to save Instructors Availability');
          } else {
            res.status(200).send('Availability saved sucessfully');
          }

        }
      );

    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server Error');
  }

});

//GETTING THE BOOKINGS FOR A SPECIFIC INSTRUCTOR 
server.get('/getInstructorbookings/userId', async (req, res) => {
  const userId = req.query.userId;

  if (!instructorId) {
    return res.status(400).json({ error: 'Instructor ID is required' });
  }

  //first use ther user id to get the instructor ID
  server.get(`SELECT I_ID FROM INSTRUCTOR WHERE U_ID=?`, [userId], (err, row) => {
    try {
      if (err) {
        console.error('Failed to get the instructor id')
        res.status(500).send('Failed to get instructord Id');
      }
      if (!row) {
        console.error('No such person');
        res.status(401).send('The is no such user');
      }
      const InstructorId = row.I_ID;



      try {
        const query =
          `SELECT 
          STUDENT.S_ID ,
          STUDENT.name,
          BOOKING.date, 
          BOOKING.StartTime  
          BOOKING.EndTime 
      FROM 
          BOOKING 
      JOIN 
          STUDENT  ON BOOKING.S_ID = STUDENT.S_ID
      WHERE 
          BOOKING.I_ID = ? `;
        db.all(query, [InstructorId], (err, rows) => {

          if (err) {
            console.error(err);
            return res.status(500).send('Failed to fetch booking');
          }
          res.status(200).json(rows);
        });


      } catch (error) {
        console.error('Error fetching bookings:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }

    } catch (error) {
      console.error('something went wrong');
    }
  });

});


//END POINT FOR A STUDENT TO BOOK FOR A SPECIFIC LESSON
server.post('/bookings/:userId/:instructorId/:packageId/:lessonId', async (req, res) => {
  const { userId, instructorId, packageId, lessonId } = req.params;
  const { date, startTime, endTime } = req.body;
  console.log(userId, instructorId, packageId, date, startTime, endTime);


  try {
    // Validate input
    if (!userId || !instructorId || !packageId || !lessonId || !date || !startTime || !endTime) {
      return res.status(400).send('Missing required parameters');
    }

    // First get the student ID
    db.get(`SELECT S_ID FROM STUDENT WHERE U_ID = ?`, [userId], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Failed to get the student ID');
      }

      if (!row) {
        return res.status(404).send('Student not found');
      }

      const s_id = row.S_ID;
      console.log(s_id);

      const sql = `
      INSERT INTO BOOKING (S_ID, I_ID, P_ID, L_ID, date, StartTime, EndTime,datecreated)
      VALUES (?, ?, ?, ?, ?, ?, ?,CURRENT_TIMESTAMP)
    `;
      console.log('Inserting booking with parameters:', [s_id, instructorId, packageId, lessonId, date, startTime, endTime]);
      // Execute the query



      db.run(sql, [s_id, instructorId, packageId, lessonId, date, startTime, endTime], function (err) {
        if (err) {
          console.error(err);
          return res.status(500).send('Failed to create booking');
        }

        /* //Decrement the number of lessons for a package 
         db.run('UPDATE PACKAGES SET noLessons =noLessons -1 WHERE P_ID= ?', [packageId], function (err) {
           if (err) {
             console.error(err);
             return res.status(500).send('Failed to create booking');
           }*/


        //returning the booking information for the front end
        res.status(201).json({
          bookingId: this.lastID,
          date,
          startTime,
          endTime

        });
      });
    });




  } catch (error) {
    console.error(error);
  }
});

//get all the availalable dates for the indtructor 
server.get('/availability-dates/:instructorId', (req, res) => {
  const { instructorId } = req.params;

  const query =
    `
SELECT DISTINCT date 
FROM INSTRUCTORSAVAILABILITY
WHERE I_ID =?
      `;

  db.all(query, [instructorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Could not fetch availability dates');
    }

    res.status(200).json(rows);
    console.log(rows);
  });

});

//GET  THE TIMES OF THE INDTUCTOR ON A SPECIFIC DATE  
server.get('/availability/:instructorId/:date', (req, res) => {
  const { instructorId, date } = req.params;

  const query =
    `
SELECT StartTime, EndTime 
FROM INSTRUCTORSAVAILABILITY
WHERE I_ID =? AND date =?
      `;


  db.all(query, [instructorId, date], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch availability');
    }
    res.status(200).json(rows);
    console.log(rows);
  });
});


//FETCHING THE INSTRUCTORS BOOKING TO DISPLAY IN THE FRONT END BOOKINGS FOR THE INSTRUCTOR 
server.get('/GetInstructorinstructor/:userId', (req, res) => {

  const userId = req.params.userId;



  db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID= ?', [userId], (err, row) => {
    if (err) {
      console.error('failed to fetch instructoe id');
      res.status(500).send('failed to get instructor');
    }


    if (!row) {
      return res.status(404).send('Student not found');
    }

    const instructorID = row.I_ID;
    console.log(instructorID);


    const query = `
    SELECT BOOKING.I_ID, BOOKING.S_ID, BOOKING.date, BOOKING.StartTime, BOOKING.EndTime,
      USER.name, USER.surname, USER.email, STUDENT.cellphoneNo
    FROM BOOKING 
    JOIN STUDENT  ON BOOKING.S_ID = STUDENT.S_ID
    JOIN USER ON STUDENT.U_ID = USER.U_ID
    WHERE BOOKING.I_ID = ? `;

    db.all(query, [instructorID], (err, rows) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(rows);
      console.log(rows);
    });


  });
});

// GETTING THE STUDENTS DETAILS 
server.get('/students/:studentID', (req, res) => {
  const studentID = req.params.studentID;

  const query = `
    SELECT USER.name, USER.surname, USER.email, STUDENT.cellphoneNo
    FROM STUDENT
    JOIN USER ON STUDENT.U_ID = USER.U_ID
    WHERE STUDENT.S_ID = ? `;

  db.get(query, [studentID], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json(row);
  });
});


//Getting the students booking 
server.get('/getStudentBooking/:studentId/:lessonId', (req, res) => {
  const studentId = req.params.studentId;
  const lessonId = req.params.lessonId;

  const query = `
      SELECT 
        
          date,
          StartTime,
          EndTime
      FROM 
          BOOKING 
      WHERE 
          S_ID = ? AND L_ID = ?;
  `;

  db.all(query, [studentId, lessonId], (err, rows) => {
    if (err) {
      console.error(err.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } else {
      res.json({ bookings: rows });
    }
  });
});

server.delete('/cancel-booking/:userId/:lessonId', async (req, res) => {
  const { userId, lessonId } = req.params;

  if (!userId || !lessonId) {
    return res.status(400).json({ error: 'User ID and Lesson ID are required' });
  }

  try {
    const studentId = await getStudentIdByUserId(userId);

    if (!studentId) {
      return res.status(404).json({ error: 'Student not found' });
    }

    db.run(
      `DELETE FROM BOOKING WHERE S_ID = ? AND L_ID = ?`,
      [studentId, lessonId],
      function (err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to cancel booking' });
        }
        res.status(200).json({ message: 'Booking cancelled successfully' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

server.post('/display-selected-package', (req, res) => {
  const {  userId, packageId } = req.body;
  console.log(req.body);

  if ( !userId || !packageId) {
    return res.status(400).send({ message: 'Please fill in all the required fields' });
  }

  console.log(`Received userId: ${userId}`);

  db.get('SELECT S_ID FROM STUDENT WHERE U_ID = ?', [userId], (err, student) => {
    if (err) {
      console.error(err);
      return res.status(500).send({ message: 'Failed to retrieve student ID' });
    }

    if (student) {
      const studentId = student.S_ID;

      db.get('SELECT * FROM PACKAGES WHERE P_ID = ?', [packageId], (err, package) => {
        if (err) {
          console.error(err);
          return res.status(500).send({ message: 'Failed to fetch package' });
        }

        if (package) {
          db.run('INSERT INTO STUDENT_PACKAGE (S_ID, P_ID, remaining_lessons) VALUES (?, ?, ?)', [studentId, packageId, package.noLessons], function (err) {
            if (err) {
              console.error(err);
              return res.status(500).send({ message: 'Failed to purchase package' });
            }
            res.status(200).send({ message: 'Payment successful and package purchased May to book' });
          });
        } else {
          res.status(404).send({ message: 'No such package' });
        }
      });
    } else {
      res.status(404).send({ message: 'Student not Registered' });
    }
  });
});











server.get('/api/instructorId', (req, res) => {
  const { U_ID } = req.query;


  const query = 'SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?';

  db.get(query, [U_ID], (err, row) => {
    if (err) {
      console.error('Database error:', err.message);
      return res.status(500).json({ error: err.message });
    }

    if (row) {
      res.json({ I_ID: row.I_ID });
    } else {
      res.status(404).json({ error: 'Instructor ID not found' });
    }
  });
});



server.get('/api/ratings', (req, res) => {
  const { I_ID } = req.query;

  const query = `
      SELECT 
          RATINGS.Rating, 
          RATINGS.Comment, 
          LESSON.name AS LessonName 
      FROM 
          RATINGS 
      JOIN 
          LESSON ON RATINGS.L_ID = LESSON.L_ID
      WHERE 
          RATINGS.I_ID = ?`;

  db.all(query, [I_ID], (err, rows) => {
    if (err) {
      console.error('Database error:', err.message);
      return res.status(500).json({ error: err.message });
    }

    res.json(rows);
  });
});

server.get('/getinstructors', (req, res) => {
  const query = `
    SELECT 
      INSTRUCTOR.I_ID,
      USER.name,
      USER.surname,
      IFNULL(AVG(RATINGS.Rating), 0) as avgRating,
      IFNULL(COUNT(BOOKING.B_ID), 0) as totalBookings -- Count total bookings
    FROM 
      INSTRUCTOR
    JOIN 
      USER ON INSTRUCTOR.U_ID = USER.U_ID
    LEFT JOIN 
      RATINGS ON INSTRUCTOR.I_ID = RATINGS.I_ID
    LEFT JOIN 
      BOOKING ON INSTRUCTOR.I_ID = BOOKING.I_ID
    GROUP BY 
      INSTRUCTOR.I_ID, USER.name, USER.surname
  `;

  db.all(query, (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch instructors');
    }
    res.status(200).json(rows);
    console.log(rows);
  });
});









////abo

// Endpoint to fetch criteria for a specific lesson
server.get('/lesson/:lessonId/student/:studentId/criteria', (req, res) => {
  const lessonId = req.params.lessonId;
  const studentId = req.params.studentId;

  console.log('Fetching criteria for lesson ID:', lessonId, 'and student ID:', studentId);

  db.all(`
     SELECT CRITERIA.CR_Name, MARKS.MARK
        FROM MARKS
        JOIN CRITERIA ON MARKS.CR_ID = CRITERIA.CR_ID
        WHERE MARKS.S_ID = ? AND MARKS.L_ID = ?
  `, [lessonId, studentId], (err, rows) => {
    if (err) {
      console.error('Error fetching criteria:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    console.log('Criteria Data:', rows);
    res.json(rows);
  });
});


// Endpoint to fetch students
server.get('/students', (req, res) => {
  db.all('SELECT STUDENT.S_ID, USER.name, USER.surname FROM STUDENT JOIN USER ON STUDENT.U_ID = USER.U_ID', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

//fetch catagories
server.get('/categories', (req, res) => {
  db.all('SELECT * FROM LESSON', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

//fetch criteria
server.get('/criteria/:lessonId', (req, res) => {
  const L_ID = req.params.lessonId;
  db.all('SELECT CR_ID, CR_Name FROM CRITERIA WHERE L_ID = ?', [L_ID], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

//input marks
server.post('/marks', (req, res) => {
  const { S_ID, L_ID, I_ID, MARK, OVERALL_SCORE, STATUS } = req.body;


  if (!S_ID || !L_ID || !I_ID || !MARK || !Array.isArray(MARK) || MARK.length === 0 || OVERALL_SCORE === undefined || !STATUS) {
    return res.status(400).json({ error: 'Invalid input data' });
  }


  db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?', [I_ID], (err, row) => {
    if (err) {
      console.error('Error fetching instructor ID:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Instructor ID not found' });
    }

    const I_ID = row.I_ID;
    console.log('Instructor ID:', I_ID);

    // Insert marks into the Marks table
    const markPromises = MARK.map(markObj => {
      return new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO MARKS (S_ID, L_ID, CR_ID, MARK) VALUES (?, ?, ?, ?)`,
          [S_ID, L_ID, markObj.CR_ID, markObj.MARK],
          function (err) {
            if (err) {
              console.error('Error inserting mark:', err);
              reject(err);
            } else {
              resolve();
            }
          }
        );
      });
    });

    Promise.all(markPromises)
      .then(() => {

        // Insert overall mark and status into PROGRESS table
        db.run(
          `INSERT INTO PROGRESS (S_ID, L_ID, I_ID, OVERALL_SCORE, STATUS) VALUES (?, ?, ?, ?, ?)`,
          [S_ID, L_ID, I_ID, OVERALL_SCORE, STATUS],
          function (err) {
            if (err) {
              console.error('Error inserting progress:', err);
              res.status(500).json({ error: err.message });
            } else {
              res.json({ message: 'Scores submitted successfully' });
            }
          }
        );
      })

      .catch(err => {
        console.error('Error in markPromises:', err);
        res.status(500).json({ error: err.message });
      });
  });
});

// Endpoint to get progress data for a specific lesson
server.get('/student/:userId/lesson/:lessonId/progress', (req, res) => {
  const userId = req.params.userId;
  const lessonId = req.params.lessonId;

  console.log('Received request with userId:', userId, 'and lessonId:', lessonId);

  // First, fetch the studentId from the userId
  db.get('SELECT S_ID FROM STUDENT WHERE U_ID = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error fetching student ID:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const studentId = row.S_ID;

    // Now, fetch the progress data using studentId and lessonId
    db.all(`
      SELECT PROGRESS.OVERALL_SCORE,PROGRESS.datecreated, LESSON.name 
        FROM PROGRESS 
        JOIN LESSON  ON PROGRESS.L_ID = LESSON.L_ID
        WHERE PROGRESS.S_ID = ? AND PROGRESS.L_ID = ?
    `, [studentId, lessonId], (err, rows) => {
      if (err) {
        console.error('Error fetching progress data:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (rows.length === 0) {
        return res.status(404).json({ error: 'No progress data found for this lesson' });
      }

      res.status(200).json(rows);
    });
  });
});

//enpoint for passed or failed students
// Endpoint to get pass/fail count for a specific lesson
server.get('/lesson/:lessonId/report', (req, res) => {
  const lessonId = req.params.lessonId;

  db.all(`
      SELECT STATUS, COUNT(*) as count
      FROM PROGRESS
      WHERE L_ID = ?
      GROUP BY STATUS
  `, [lessonId], (err, rows) => {
    if (err) {
      console.error('Error fetching report data:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    // If no rows are returned, send an empty result
    if (rows.length === 0) {
      return res.status(404).json({ error: 'No report data found' });
    }

    res.status(200).json(rows);
  });
});

//code for overall progress (all lessons combine
server.get('/student/:userId/overall-progress', (req, res) => {
  const userId = req.params.userId;
  console.log(userId);

  db.get('SELECT S_ID FROM STUDENT WHERE U_ID = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error fetching student ID:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const studentId = row.S_ID;
    console.log(studentId);

    // Query to fetch overall progress data
    const query = `
      SELECT LESSON.name, PROGRESS.OVERALL_SCORE
      FROM PROGRESS
      JOIN LESSON ON PROGRESS.L_ID = LESSON.L_ID
      WHERE PROGRESS.S_ID = ?
    `;

    db.all(query, [studentId], (err, rows) => {
      if (err) {
        console.error('Error fetching progress data:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      // Format data for the chart
      const formattedData = rows.map(row => ({
        lessonName: row.name,
        overallScore: row.OVERALL_SCORE
      }));

      res.json(formattedData);
    });
  });
});
//progress mark student data

// Endpoint to get all lessons for a student for the graph
// Endpoint to get all lessons for a student for the graph
/*server.get('/student/:studentId/lessons', (req, res) => {
  const studentId = req.params.studentId;
  console.log(`Fetching lessons for student ID: ${studentId}`); // Debugging 
  db.all(`SELECT LESSON.L_ID, LESSON.name 
      FROM LESSON
      JOIN PROGRESS ON LESSON.L_ID = PROGRESS.L_ID
      WHERE PROGRESS.S_ID = ?
    
  `, [studentId], (err, rows) => {
      if (err) {
          console.error('Error fetching lessons:', err);
          return res.status(500).json({ error: 'Internal Server Error' });
      }
      console.log('Lessons Data:', rows);
      res.json(rows);
  });
});

 /* 

//endpoint for criteria for graph
server.get('/student/:studentId/lesson/:lessonId/progress', (req, res) => {
  const studentId = req.params.studentId;
  const lessonId = req.params.lessonId;

  db.all(`
     SELECT CRITERIA.CR_Name, MARKS.MARK
        FROM MARKS
        JOIN CRITERIA ON MARKS.CR_ID = CRITERIA.CR_ID
        WHERE MARKS.S_ID = ? AND MARKS.L_ID = ?
  `, [studentId, lessonId], (err, rows) => {
      if (err) {
          console.error('Error fetching progress data:', err);
          return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json(rows);
  });
});
*/
/* Endpoint to get student progress data
server.get('/student-progress/:studentId', (req, res) => {
  const studentId = req.params.studentId;

  const sql = `
      SELECT PROGRESS.L_ID, MARKS.MARK
      FROM PROGRESS
      JOIN MARKS ON PROGRESS.S_ID = MARKS.S_ID AND PROGRESS.L_ID = MARKS.L_ID
      WHERE PROGRESS.S_ID = ?
      GROUP BY PROGRESS.L_ID
  `;

  db.all(sql, [studentId], (err, rows) => {
      if (err) {
          console.error('Error fetching student progress data:', err.message);
          res.status(500).json({ error: 'Failed to fetch student progress data' });
      } else {
          const marks = rows.map(row => ({
              L_ID: row.L_ID,
              MARK: row.MARK
          }));
          res.json({ marks });
      }
  });
});

/*Example endpoint to get student progress data
server.get('/student-progress/:studentId', async (req, res) => {
  const studentId = req.params.studentId;

  try {
      // Fetch marks from the MARKS table
      const marksQuery = `SELECT CR_ID, MARK 
                          FROM MARKS
                          WHERE S_ID = ?
                          GROUP BY CR_ID`;
      const marks = await db.all(marksQuery, [studentId]);

      // Fetch progress data from the PROGRESS table
      const progressQuery = `SELECT L_ID, OVERALL_SCORE, STATUS
                             FROM PROGRESS
                             WHERE S_ID = ?`;
      const progress = await db.all(progressQuery, [studentId]);

      // Combine marks and progress data
      const result = {
          marks: marks,
          progress: progress
      };

      res.json(result);
  } catch (error) {
      console.error('Error fetching student progress data:', error);
      res.status(500).json({ error: 'Failed to fetch progress data' });
  }
});
*/

// get instructors
// Server-side code
server.get('/score-student/:userId', (req, res) => {
  const userId = req.params.userId;
  if (!userId) {
    return res.status(401).send('User not authenticated');
  }

  // Retrieve the instructor ID from the database
  db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error fetching instructor ID:', err);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.status(404).send('Instructor not found');
    }

    const instructorId = row.I_ID;
    res.json({ instructorId });
  });
});



// get instructors
// Server-side code
server.get('/score-student/:userId', (req, res) => {
  const userId = req.params.userId;
  if (!userId) {
    return res.status(401).send('User not authenticated');
  }

  // Retrieve the instructor ID from the database
  db.get('SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error fetching instructor ID:', err);
      return res.status(500).send('Internal Server Error');
    }

    if (!row) {
      return res.status(404).send('Instructor not found');
    }

    const instructorId = row.I_ID;
    res.json({ instructorId });
  });
});
//ENDPOINTS FOR MARKS AND PROGRESS
server.get('/student/:userId/progress', (req, res) => {
  const userId = req.params.userId;
  console.log(userId);
  //const requestedUserId = req.params.userId;


  // if (userId !== loggedInUserId) {

  //   console.log('Requested userId:', req.params.userId);
  // }
  db.get('SELECT S_ID FROM STUDENT WHERE U_ID = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error fetching student ID:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const studentId = row.S_ID;

    db.all(`
          SELECT LESSON.name, PROGRESS.OVERALL_SCORE, PROGRESS.STATUS
          FROM PROGRESS
          JOIN LESSON ON PROGRESS.L_ID = LESSON.L_ID
          WHERE PROGRESS.S_ID = ?
          
      `, [studentId], (err, row) => {
      if (err) {
        console.error('Error fetching progress data:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (!row) {
        return res.status(404).json({ error: 'No progress data found' });
      }

      console.log('Progress Data:', row);  // Debugging line
      res.status(200).json(row);
    });
  });
});
// New endpoint to get total bookings per month for an instructor
server.get('/instructor-bookings/:instructorId', (req, res) => {
  const instructorId = req.params.instructorId;

  // SQL query to count bookings grouped by month
  const query = `
      SELECT 
          strftime('%Y-%m', BOOKING.datecreated) AS month,  -- Group by year and month
          COUNT(B_ID) AS totalBookings 
      FROM 
          BOOKING 
      WHERE 
          I_ID = ? 
      GROUP BY 
          month 
      ORDER BY 
          month
  `;

  db.all(query, [instructorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch instructor bookings');
    }
    res.status(200).json(rows);
  });
});
// New endpoint to get instructor comments
server.get('/instructor-comments/:instructorId', (req, res) => {
  const { instructorId } = req.params;

  // Query to get the comments for a specific instructor
  const query = `
    SELECT 
      USER.name AS studentName,
      RATINGS.Comment AS comment
    FROM 
      RATINGS
    JOIN 
      USER ON RATINGS.S_ID = USER.U_ID
    WHERE 
      RATINGS.I_ID = ?
  `;

  // Use the instructorId provided by the client in the request
  db.all(query, [instructorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch instructor comments');
    }
    res.status(200).json(rows);
  });
});

server.get('/instructor/:instructorId/students', (req, res) => {
  // Get the userId from the request (make sure to pass this from the client-side)
  console.log('hello');
  const instructorId = req.params.instructorId;
  console.log(instructorId);

  // Fetch the instructor ID associated with the userId
  const getInstructorIdQuery = `SELECT I_ID FROM INSTRUCTOR WHERE U_ID = ?`;

  db.get(getInstructorIdQuery, [instructorId], (err, row) => {
    console.log(instructorId);
    if (err) {
      console.error('Error fetching instructor ID:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Instructor not found' });
    }

    const InsId = row.I_ID;

    // Now fetch students associated with the instructor ID
    const query = `
            SELECT  USER.U_ID, USER.name,USER.surname
            FROM PROGRESS
            INNER JOIN STUDENT ON PROGRESS.S_ID = STUDENT.S_ID
            INNER JOIN USER ON STUDENT.U_ID = USER.U_ID
            WHERE PROGRESS.I_ID = ?`;

    db.all(query, [InsId], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);
      console.log(rows);
    });
  });
});

///newly eny
server.get('/fetch-all-reviews', (req, res) => {

  const query = `
    SELECT USER.name, USER.surname, RATINGS.Rating, RATINGS.Comment
    FROM RATINGS 
    JOIN STUDENT ON RATINGS.S_ID = STUDENT.S_ID
    JOIN USER  ON STUDENT.U_ID = USER.U_ID;
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);

    console.log('hello');
  });
});


server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
