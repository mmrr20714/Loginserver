const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();

const app = express();

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./app.db");

// =====================
// INIT DB
// =====================
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            salt TEXT,
            created_at INTEGER
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT,
            created_at INTEGER
        )
    `);
});

// =====================
// LOGGER (حرفه‌ای‌تر)
// =====================
function log(type, msg) {
    const time = new Date().toISOString();
    console.log(`[${time}] [${type}] ${msg}`);
}

// =====================
// PASSWORD HASH
// =====================
function hashPassword(password, salt = null) {
    salt = salt || crypto.randomBytes(16).toString("hex");

    const hash = crypto
        .pbkdf2Sync(password, salt, 12000, 64, "sha512")
        .toString("hex");

    return { hash, salt };
}

// =====================
// REGISTER
// =====================
app.post("/api/register", (req, res) => {
    const { username, password } = req.body;

    log("REGISTER", `${username} trying to create account`);

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "Username/password required"
        });
    }

    if (username.length < 3 || password.length < 4) {
        return res.status(400).json({
            success: false,
            message: "Too short credentials"
        });
    }

    const { hash, salt } = hashPassword(password);

    db.run(
        `INSERT INTO users (username, password, salt, created_at)
         VALUES (?, ?, ?, ?)`,
        [username, hash, salt, Date.now()],
        function (err) {
            if (err) {
                log("REGISTER FAIL", `${username} already exists`);
                return res.status(409).json({
                    success: false,
                    message: "Username already exists"
                });
            }

            log("REGISTER SUCCESS", `${username} created`);

            res.json({
                success: true,
                message: "Account created"
            });
        }
    );
});

// =====================
// LOGIN
// =====================
app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    log("LOGIN", `${username} attempt`);

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "Missing fields"
        });
    }

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        (err, user) => {
            if (err || !user) {
                log("LOGIN FAIL", `${username} not found`);
                return res.status(401).json({
                    success: false,
                    message: "Invalid credentials"
                });
            }

            const { hash } = hashPassword(password, user.salt);

            if (hash !== user.password) {
                log("LOGIN FAIL", `${username} wrong password`);
                return res.status(401).json({
                    success: false,
                    message: "Invalid credentials"
                });
            }

            const token = crypto.randomBytes(32).toString("hex");

            db.run(
                `INSERT INTO sessions (token, username, created_at)
                 VALUES (?, ?, ?)`,
                [token, username, Date.now()]
            );

            log("LOGIN SUCCESS", `${username} logged in`);

            res.json({
                success: true,
                token
            });
        }
    );
});

// =====================
// SESSION CHECK (با expiry)
// =====================
app.post("/api/check-session", (req, res) => {
    const { token } = req.body;

    db.get(
        `SELECT * FROM sessions WHERE token = ?`,
        [token],
        (err, session) => {
            if (err || !session) {
                return res.status(401).json({
                    valid: false
                });
            }

            // ⛔ session expiry (7 days)
            const week = 7 * 24 * 60 * 60 * 1000;

            if (Date.now() - session.created_at > week) {
                db.run(`DELETE FROM sessions WHERE token = ?`, [token]);

                return res.status(401).json({
                    valid: false,
                    message: "Session expired"
                });
            }

            res.json({
                valid: true,
                username: session.username
            });
        }
    );
});

// =====================
app.listen(3000, () => {
    log("SERVER", "Running on port 3000");
});