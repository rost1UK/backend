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

db.run(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT,
  password TEXT,
  role TEXT DEFAULT 'user'
)`);

db.run(`CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY,
  title TEXT,
  userId INTEGER,
  completed INTEGER DEFAULT 0
)`);

// ADMIN AUTO
db.get("SELECT * FROM users WHERE role='admin'", async (e,u)=>{
  if(!u){
    const hash = await bcrypt.hash("admin",10);
    db.run("INSERT INTO users(username,password,role) VALUES (?,?,?)",
      ["admin",hash,"admin"]);
  }
});

// LOGIN
app.post("/login",(req,res)=>{
  db.get("SELECT * FROM users WHERE username=?",
  [req.body.username], async (e,user)=>{

    if(!user) return res.sendStatus(400);

    const ok = await bcrypt.compare(req.body.password,user.password);
    if(!ok) return res.sendStatus(400);

    const token = jwt.sign({
      id:user.id,
      role:user.role
    },SECRET);

    res.json({token});
  });
});

// AUTH
function auth(req,res,next){
  const token = req.headers.authorization;
  if(!token) return res.sendStatus(401);

  try{
    req.user = jwt.verify(token,SECRET);
    next();
  }catch{
    res.sendStatus(403);
  }
}

// TASKS (USER ONLY)
app.post("/tasks",auth,(req,res)=>{
  db.run(
    "INSERT INTO tasks(title,userId) VALUES (?,?)",
    [req.body.title,req.user.id],
    function(){res.json({id:this.lastID});}
  );
});

app.get("/tasks",auth,(req,res)=>{
  db.all("SELECT * FROM tasks WHERE userId=?",
  [req.user.id],(e,r)=>res.json(r));
});

// ADMIN CHECK
function admin(req,res,next){
  if(req.user.role !== "admin") return res.sendStatus(403);
  next();
}

// ALL USERS (ADMIN)
app.get("/users",auth,admin,(req,res)=>{
  db.all("SELECT id,username,role FROM users",
  (e,r)=>res.json(r));
});

// REPORT (ADMIN)
app.get("/report",auth,admin,(req,res)=>{
  db.all(`
    SELECT users.username, tasks.title
    FROM users
    LEFT JOIN tasks ON users.id = tasks.userId
  `,(e,r)=>res.json(r));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT);
