const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));

// Serve static files
app.use(express.static(__dirname));

// Sign Up Route
app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
        if (err) {
            return res.status(500).send("Error registering user.");
        }
        res.redirect('/login.html');
    });
});

// Log In Route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).send("User not found.");
        }

        const user = results[0];
        const isPasswordValid = bcrypt.compareSync(password, user.password);

        if (isPasswordValid) {
            req.session.username = user.username;
            res.redirect('/success.html');
        } else {
            res.status(401).send("Invalid password.");
        }
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
