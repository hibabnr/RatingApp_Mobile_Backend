const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
require('dotenv').config(); 


const app = express();
const port = 8000;

app.use(bodyParser.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'rating'
});


app.post('/signup', (req, res) => {
  const { first_name, last_name, email, password, user_type_id } = req.body;

  if (!first_name || !last_name || !email || !password || !user_type_id) {
    return res.status(400).json({ error: "All fields are required" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, data) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (data.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    } else {
      bcrypt.hash(password.toString(), 10, (err, hashedPassword) => {
        if (err) {
          console.error('Password hashing error:', err);
          return res.status(500).json({ error: "Error hashing password" });
        }

        db.query("INSERT INTO users (first_name, last_name, email, password, user_type_id) VALUES (?, ?, ?, ?, ?)",
          [first_name, last_name, email, hashedPassword, user_type_id], (err) => {
            if (err) {
              return res.status(500).json({ error: "Error inserting user into database", err: err });
            } else {
              const token = jwt.sign({ email: email }, process.env.JWT_SECRET, { expiresIn: '1d' });
              return res.status(201).json({ status: "Success", token: token });
            }
          });
      });
    }
  });
});


  app.post('/login', (req, res) => {
    const {email,password} = req.body;

    if ( !email || !password ) {
        return res.status(400).json({ error: "All fields are required" });
      }

  db.query("SELECT * FROM Users WHERE email = ?", [email], (err, data) => {
    if (err) return res.json({ Error: "Error fetching data from database.", err: err });
    if (data.length > 0) {
      bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
        if (err) return res.json({ Error: "Password compare error" });
        if (response) {
          const email = data[0].email;
          const token = jwt.sign({ email: email }, process.env.JWT_SECRET, { expiresIn: '1d' });
          return res.status(201).json({ Status: "Success", token: token });
        } else {
          return res.json({ Error: "Password is incorrect!" });
        }
      });
    } else {
      return res.json({ Error: "email does not exist " });
    }
  });
});
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
