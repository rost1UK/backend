const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = "secret";

// DB
const db = new sqlite3.Database("db.sqlite");

// INIT TABLES
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT,
  role TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  userId INTEGER,
  completed INTEGER
)`);

// AUTO ADMIN
db.get("SELECT * FROM users WHERE role='admin'", async (e, u) => {
  if (!u) {
    const hash = await bcrypt.hash("admin", 10);
    db.run(
      "INSERT INTO users (username,password,role) VALUES (?,?,?)",
      ["admin", hash, "admin"]
    );
  }
});

// AUTH MIDDLEWARE
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

// LOGIN
app.post("/login", (req, res) => {
  db.get(
    "SELECT * FROM users WHERE username=?",
    [req.body.username],
    async (e, user) => {
      if (!user) return res.sendStatus(400);

      const ok = await bcrypt.compare(req.body.password, user.password);
      if (!ok) return res.sendStatus(400);

      const token = jwt.sign(
        { id: user.id, role: user.role },
        SECRET
      );

      res.json({ token });
    }
  );
});

// TASK CREATE
app.post("/tasks", auth, (req, res) => {
  db.run(
    "INSERT INTO tasks (title,userId,completed) VALUES (?,?,0)",
    [req.body.title, req.user.id],
    function () {
      res.json({ id: this.lastID });
    }
  );
});

// GET TASKS
app.get("/tasks", auth, (req, res) => {
  db.all(
    "SELECT * FROM tasks WHERE userId=?",
    [req.user.id],
    (e, rows) => res.json(rows)
  );
});

// COMPLETE TASK
app.put("/tasks/:id", auth, (req, res) => {
  db.run(
    "UPDATE tasks SET completed=1 WHERE id=?",
    [req.params.id],
    () => res.sendStatus(200)
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("RUNNING"));