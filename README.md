# Communication_LTD Web Application 🚀

Welcome to the Communication_LTD web application! This project is designed to manage client information securely and efficiently. Below you will find all the necessary information to set up and run the project.



# Prerequisites 🛠️

Ensure you have the following installed:

- Node.js
- npm
- PostgreSQL

# Installation 💻

1. Clone the repository:
git clone https://github.com/your-username/communication_ltd.git
cd communication_ltd


2. Install dependencies:

3. Set up the database:

- Create a PostgreSQL database named `postgres`.
- Configure your database connection in `config.json`.

# Configuration ⚙️

Create a `config.json` file in the root directory with the following content:

```json
{
"password": {
 "minLength": 8,
 "requireUppercase": true,
 "requireLowercase": true,
 "requireNumbers": true,
 "requireSpecialCharacters": true,
 "passwordHistoryLimit": 5
}
}

# Communication_LTD Web Application 🚀

## Usage

To start the server, run:
node app.js
The server will run on port 3002 by default.

```


# Routes

- **GET /login** - Serve login page.
- **GET /register** - Serve registration page.
- **GET /logout** - Log out the user.
- **GET /forgotpassword** - Serve forgot password page.
- **POST /forgotPassword** - Handle forgot password request.
- **GET /reset/:token** - Serve reset password page.
- **POST /resetPassword** - Handle reset password request.
- **GET /changepassword** - Serve change password page.
- **POST /changePassword** - Handle change password request.
- **GET /main** - Serve main page after login.
- **POST /register** - Handle user registration.
- **POST /login** - Handle user login.
- **POST /addClient** - Add a new client (Requires authentication).

# Security Concerns 🛡️

## Current Vulnerabilities:
- **SQL Injection:**
  - The registration and login routes are vulnerable to SQL injection as they use unparameterized queries.
- **XSS (Cross-Site Scripting):**
  - The addClient route reflects user input directly into the HTML without proper sanitation.


# Contributing 🤝

1. Fork the project.
2. Create your feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

# License 📜

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Feel free to contribute to this project by fixing vulnerabilities, adding features, or improving documentation. Happy coding! 🎉

For any questions or issues, please open an issue on GitHub.

