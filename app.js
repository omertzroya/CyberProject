const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();
const path = require('path');
const { Client } = require('pg');
const nodemailer = require('nodemailer');
const fs = require('fs');
const bodyParser = require('body-parser');

// Loading configuration file
const config = JSON.parse(fs.readFileSync('config.json'));

// Setup email transporter
const transporter = nodemailer.createTransport({
    service: 'Gmail', // or any other email service
    auth: {
        user: 'best4mecomp@gmail.com',
        pass: 'pdhmsyzlivvdzplw'
    }
});

// Generate a random secret key
const secretKey = crypto.randomBytes(128).toString('hex');

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
    secret: secretKey,
    resave: false,
    saveUninitialized: false
}));

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Start the server
const port = process.env.PORT || 3002; // or any port of your choice
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// Database connection
const db = new Client({
    user: "postgres",
    host: "localhost",
    database: "postgres",
    password: "123456",
    port: 5432,
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to database', err.stack);
    } else {
        console.log('Connected to database');
    }
});



// Load dictionarty file
const dictionary = fs.readFileSync(config.password.dictionaryPath,'utf8').split('\n');

// password complexity check
function isPasswordComplex(password) {
    const { minLength, requireUppercase, requireLowercase, requireNumbers, requireSpecialCharacters, requireDictionaryProtection } = config.password;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    const existInDictionary = !dictionary.includes(password);


    return password.length >= minLength &&
           (!requireUppercase || hasUppercase) &&
           (!requireLowercase || hasLowercase) &&
           (!requireNumbers || hasNumbers) &&
           (!requireDictionaryProtection || existInDictionary) &&
           (!requireSpecialCharacters || hasSpecial);
}


// password hashing with HMAC + Salt
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHmac('sha256', salt).update(password).digest('hex');
    return { salt, hash };
}

// Defined routes
app.get('/login', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            res.status(500).send('Error logging out');
        } else {
            res.redirect('/login'); 
        }
    });
});

app.get('/forgotpassword', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgotpassword.html'));
});

app.post('/forgotPassword', async (req, res) => {
    const { email } = req.body;

    try {
        const result = await db.query("SELECT username FROM usersunsecure WHERE email = $1", [email]);

        if (result.rows.length === 0) {
            return res.status(400).send('An e-mail has been sent with further instructions in the case this email exists');
        }

        const username = result.rows[0].username;

        // Random token created with sha1
        // Token valid for 1 hour
        const token = crypto.randomBytes(20).toString('hex');
        const hash = crypto.createHash('sha1').update(token).digest('hex');
        const expiry = new Date(Date.now() + 3600000); 

        await db.query("UPDATE usersunsecure SET reset_token = $1, reset_token_expiry = $2 WHERE username = $3", [hash, expiry, username]);

        const mailOptions = {
            to: email,
            from: 'best4mecomp@gmail.com',
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                  `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                  `http://${req.headers.host}/reset/${token}\n\n` +
                  `If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        transporter.sendMail(mailOptions, (err,info) => {
            if (err) {
                console.error('Error sending email:', err);
                return res.status(500).send('Error sending email');
            } else {
                console.log('Email sent: ' + info.response);
            }
            res.status(200).send('An e-mail has been sent with further instructions in the case this email exists');
        });
    } catch (error) {
        console.error('Error processing forgot password:', error);
        res.status(500).send('Error processing forgot password');
    }
});

app.get('/reset/:token', (req, res) => {
    const token = req.params.token;
    res.render('resetpassword', { token });
});


app.post('/resetPassword', async (req, res) => {
    const { token, newPassword, repeatPassword } = req.body;

    try {
        if (newPassword !== repeatPassword) {
            return res.status(400).send('Passwords do not match');
        }

        
        if (!isPasswordComplex(newPassword)) {
            return res.status(400).send('New password does not meet complexity requirements');
        }

        
        const hash = crypto.createHash('sha1').update(token).digest('hex');
        const result = await db.query("SELECT username, reset_token_expiry FROM usersunsecure WHERE reset_token = $1", [hash]);

        if (result.rows.length === 0) {
            return res.status(400).send('Invalid or expired token');
        }

        const { username, reset_token_expiry } = result.rows[0];

        if (await isPasswordInHistory(username, newPassword)) {
            return res.status(400).send('New password does not meet complexity requirements');
        }

        if (reset_token_expiry < new Date()) {
            return res.sendFile(path.join(__dirname, 'public', 'error.html'));
        }

        await db.query("UPDATE usersunsecure SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE username = $2", [newPassword, username]);

        res.status(200).send('Password has been reset successfully');
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send('Error resetting password');
    }
});


app.get('/changepassword', async (req, res) => {
    if (!req.session.username) {
        return res.sendFile(path.join(__dirname, 'public', 'error.html')); 
    }
    res.setHeader('Cache-Control', 'no-store'); 
    res.sendFile(path.join(__dirname, 'public', 'changepassword.html'));
});

app.get('/main', async (req, res) => {
    if (!req.session.username) {
        return res.sendFile(path.join(__dirname, 'public', 'error.html')); 
    }
    res.setHeader('Cache-Control', 'no-store'); 
    res.sendFile(path.join(__dirname, 'public', 'main.html'));
});


//SQL injection , write it inside password and repeat passwordF
//'); DROP TABLE users; --
// 123'); DROP TABLE usersunsecure; --F
app.post('/register', async (req, res) => {
    const { username, firstname, lastname, email, password, repeatPassword } = req.body;
    
    try {
        if (!username || !firstname || !lastname || !email || !password || !repeatPassword) {
            return res.status(400).send('All fields are required');
        }

        if (password !== repeatPassword) {
            return res.status(400).send('Passwords mismatch');
        }

        if (!isPasswordComplex(password)) {
            return res.status(400).send('Password does not meet complexity requirements');
        }

        if (await isUsernameTaken(username)) {
            return res.status(400).send('Incorret input in one or more of the fields, try again');
        }

        const query = `INSERT INTO usersunsecure (username, firstname, lastname, email, password) 
                       VALUES ('${username}', '${firstname}', '${lastname}', '${email}', '${password}')`;

        await db.query(query);

        await db.query("INSERT INTO password_history_unsecure (username, password) VALUES ($1, $2)", [username, password]);

        res.status(200).send('User registered successfully');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// SQL injection
//' OR '1'='1
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        
        // Unparameterized query (vulnerable to SQL injection)
        const query = `SELECT * FROM usersunsecure WHERE username = '${username}' AND password = '${password}' LIMIT 1`;
        const result = await db.query(query);

        if (result.rows.length === 0) {
            return res.status(401).send('Invalid username or password');
        }

        req.session.username = username;
        res.redirect('/main');

    } catch (error) {
        console.error('Error logging in:', error);
        return res.status(500).send('Error logging in');
    }
});


// Add new client (that is XSS vulnerable)
app.post('/addClient', async (req, res) => {
    const { clientFirstName, clientLastName, clientId, clientEmail, clientPhone } = req.body;

    try {
        // Check if user is authenticated
        if (!req.session.username) {
            return res.status(401).send('Unauthorized');
        }

        // Insecure query construction
        const query = `INSERT INTO clients (first_name, last_name, client_id, email, phone) 
        VALUES ('${clientFirstName}', '${clientLastName}', '${clientId}', '${clientEmail}', '${clientPhone}') RETURNING *`;

        // Execute the query
        const result = await db.query(query);

        // Check if any field is empty
        if (!clientFirstName || !clientLastName || !clientId || !clientEmail || !clientPhone) {
            return res.status(200).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Main</title>
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="flex flex-col min-h-screen bg-gray-100 font-sans antialiased">
                    <!-- Nav bar -->
                    <nav class="bg-gray-600 p-4 text-white flex justify-between">
                        <div>
                            <h1 class="text-3xl font-bold">Communication_LTD</h1>
                        </div>
                        <div>
                            <a href="changepassword" class="text-white hover:underline mx-4">Change Password</a>
                            <a href="/logout" class="text-white hover:underline mx-4">Log Out</a>
                        </div>
                    </nav>
                    <br>
                    <br>
                    <!-- Main -->
                    <div class="flex items-center justify-center h-screen">
                        <div class="bg-white p-8 shadow-md rounded-lg max-w-md w-full">
                            <!-- Form -->
                             <div class="text-center">
                        <h2 class="text-2xl font-semibold mb-5">Welcome!</h2>
                        <p class="text-gray-700 mb-5">
                            Add new client
                        </p>
                        <form id="addClientForm" class="space-y-4 text-left" action="/addClient" method="POST">
                            <div>
                                <label for="clientFirstName" class="block mb-1 font-medium">First Name</label>
                                <input type="text" id="clientFirstName" name="clientFirstName" placeholder="Enter new client first name..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientLastName" class="block mb-1 font-medium">Last Name</label>
                                <input type="text" id="clientLastName" name="clientLastName" placeholder="Enter new client last name..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientId" class="block mb-1 font-medium">ID</label>
                                <input type="text" id="clientId" name="clientId" placeholder="Enter new client ID..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientEmail" class="block mb-1 font-medium">Email</label>
                                <input type="text" id="clientEmail" name="clientEmail" placeholder="Enter new client email..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientPhone" class="block mb-1 font-medium">Phone</label>
                                <input type="text" id="clientPhone" name="clientPhone" placeholder="Enter new client phone..." class="w-full p-2 border rounded">
                            </div>

                            <button type="submit" class="w-full bg-gray-500 text-white p-2 rounded hover:bg-gray-600">Add to Database</button>
                        </form>
                            <div class="text-center">
                                <p class="text-red-600">Fill out all the client information fields</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
            `);
        }


        res.status(200).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Main</title>
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            
        </head>
        <body class="flex flex-col min-h-screen bg-gray-100 font-sans antialiased">
            <!-- Nav bar -->
            <nav class="bg-gray-600 p-4 text-white flex justify-between">
                <div>
                    <h1 class="text-3xl font-bold">Communication_LTD</h1>
                </div>
                <div>
                    <a href="changepassword" class="text-white hover:underline mx-4">Change Password</a>
                    <a href="/logout" class="text-white hover:underline mx-4">Log Out</a>
                </div>
            </nav>
            <br>
            <br>
            <!-- Main -->
            <div class="flex items-center justify-center h-screen">
                <div class="bg-white p-8 shadow-md rounded-lg max-w-md w-full">
                    <!-- Form -->
                    <div class="text-center">
                        <h2 class="text-2xl font-semibold mb-5">Welcome!</h2>
                        <p class="text-gray-700 mb-5">
                            Add new client
                        </p>
                        <form id="addClientForm" class="space-y-4 text-left" action="/addClient" method="POST">
                            <div>
                                <label for="clientFirstName" class="block mb-1 font-medium">First Name</label>
                                <input type="text" id="clientFirstName" name="clientFirstName" placeholder="Enter new client first name..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientLastName" class="block mb-1 font-medium">Last Name</label>
                                <input type="text" id="clientLastName" name="clientLastName" placeholder="Enter new client last name..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientId" class="block mb-1 font-medium">ID</label>
                                <input type="text" id="clientId" name="clientId" placeholder="Enter new client ID..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientEmail" class="block mb-1 font-medium">Email</label>
                                <input type="text" id="clientEmail" name="clientEmail" placeholder="Enter new client email..." class="w-full p-2 border rounded">
                            </div>
                            <div>
                                <label for="clientPhone" class="block mb-1 font-medium">Phone</label>
                                <input type="text" id="clientPhone" name="clientPhone" placeholder="Enter new client phone..." class="w-full p-2 border rounded">
                            </div>

                            <button type="submit" class="w-full bg-gray-500 text-white p-2 rounded hover:bg-gray-600">Add to Database</button>
                        </form>
                    <h2>Client Added Successfully</h2>
                    <table class="table-auto">
                        <tbody>
                            <tr>
                                <td class="border px-4 py-2">First Name</td>
                                <td class="border px-4 py-2">${clientFirstName}</td>
                            </tr>
                            <tr>
                                <td class="border px-4 py-2">Last Name</td>
                                <td class="border px-4 py-2">${clientLastName}</td>
                            </tr>
                            <tr>
                                <td class="border px-4 py-2">ID</td>
                                <td class="border px-4 py-2">${clientId}</td>
                            </tr>
                            <tr>
                                <td class="border px-4 py-2">Email</td>
                                <td class="border px-4 py-2">${clientEmail}</td>
                            </tr>
                            <tr>
                                <td class="border px-4 py-2">Phone</td>
                                <td class="border px-4 py-2">${clientPhone}</td>
                            </tr>
                        </tbody>
                    </table>

                    <br>
                </div>
            </div>

            <script>
                document.addEventListener('DOMContentLoaded', () => {
                    const addClientForm = document.getElementById('addClientForm');
                    const statusMessage = document.getElementById('statusMessage');
                    
                    addClientForm.addEventListener('submit', async (event) => {
                        event.preventDefault();
            
                        const formData = new FormData(addClientForm);
            
                        try {
                            const response = await fetch('/addClient', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded'
                                },
                                body: new URLSearchParams(formData)
                            });
            
                            if (!response.ok) {
                                throw new Error('Network response was not ok ' + response.statusText);
                            }
                            
                            if (response.ok) {
                                const resultHTML = await response.text();
                                
                                // Clear the existing content and write the new HTML document

                                document.open();
                                document.write(resultHTML);
                                document.close();
                            } else {
                                const errorMessage = await response.text();
                                statusMessage.innerHTML = errorMessage;
                            }
                        } catch (error) {
                            console.error('Error adding client:', error);
                            statusMessage.innerHTML = 'Error adding client';
                        }
                    });
                    });
                </script>
            </body>
            </html>`
        );


    } catch (error) {
        console.error('Error adding client:', error);
        res.status(500).send('Error adding client');
    }
});


async function isPasswordInHistory(username, newHash) {
    const historyLimit = config.password.passwordHistoryLimit;
    const result = await db.query("SELECT password FROM password_history_unsecure WHERE username = $1 ORDER BY changed_at DESC LIMIT $2", [username, historyLimit]);
    return result.rows.some(row => row.password === newHash);
}

async function isUsernameTaken(username){
    const result = await db.query("SELECT username FROM users WHERE username = $1", [username]);
    return result.rows.some(row => row.username === username);
}

app.post('/changePassword', async (req, res) => {
    if (!req.session.username) {
        return res.status(401).send('Unauthorized');
    }
    const { currentPassword, newPassword } = req.body;
    const username = req.session.username;

    try {
        const result = await db.query("SELECT password FROM usersunsecure WHERE username = $1", [username]);
        if (result.rows.length === 0) {
            return res.status(400).send('User not found');
        }

        const dbPassword = result.rows[0].password;

        if (currentPassword !== dbPassword) {
            return res.status(400).send('Current password is incorrect');
        }

        if (currentPassword === newPassword) {
            return res.status(400).send('New password must be different from the current password');
        }

        if (!isPasswordComplex(newPassword)) {
            return res.status(400).send('New password does not meet complexity requirements');
        }

        if (await isPasswordInHistory(username, newPassword)) {
            return res.status(400).send('New password does not meet complexity requirements');
        }

        await db.query("UPDATE usersunsecure SET password = $1 WHERE username = $2", [newPassword, username]);
        await db.query("INSERT INTO password_history_unsecure (username, password) VALUES ($1, $2)", [username, newPassword]);

        res.status(200).send('Password changed successfully');
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).send('Error changing password');
    }
});


