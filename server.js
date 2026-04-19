const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = "goplanner_secret_key";

// DB
const db = new sqlite3.Database("db.sqlite");

db.run(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT,
  password TEXT,
  role TEXT DEFAULT 'user',
  plan TEXT DEFAULT 'free'
)`);

db.run(`CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY,
  title TEXT,
  userId INTEGER
)`);

// ADMIN AUTO CREATE
db.get("SELECT * FROM users WHERE role='admin'", async (err,user)=>{
  if(!user){
    const hash = await bcrypt.hash("admin",10);
    db.run(
      "INSERT INTO users(username,password,role,plan) VALUES (?,?,?,?)",
      ["admin",hash,"admin","pro"]
    );
  }
});

// LOGIN
app.post("/login",(req,res)=>{
  db.get(
    "SELECT * FROM users WHERE username=?",
    [req.body.username],
    async (err,user)=>{

      if(!user) return res.status(400).json({error:"no user"});

      const ok = await bcrypt.compare(req.body.password,user.password);
      if(!ok) return res.status(400).json({error:"wrong password"});

      const token = jwt.sign({
        id:user.id,
        role:user.role,
        plan:user.plan,
        username:user.username
      },SECRET,{expiresIn:"7d"});

      res.json({token});
    }
  );
});

// AUTH
function auth(req,res,next){
  const h=req.headers.authorization;
  if(!h) return res.sendStatus(401);

  try{
    req.user = jwt.verify(h.split(" ")[1],SECRET);
    next();
  }catch{
    res.sendStatus(403);
  }
}

// ADMIN CHECK
function admin(req,res,next){
  if(req.user.role!=="admin") return res.sendStatus(403);
  next();
}

// TASKS
app.post("/tasks",auth,(req,res)=>{
  db.run(
    "INSERT INTO tasks(title,userId) VALUES (?,?)",
    [req.body.title,req.user.id],
    function(){res.json({id:this.lastID});}
  );
});

app.get("/tasks",auth,(req,res)=>{
  db.all(
    "SELECT * FROM tasks WHERE userId=?",
    [req.user.id],
    (e,r)=>res.json(r)
  );
});

// ADMIN USERS
app.get("/users",auth,admin,(req,res)=>{
  db.all(
    "SELECT id,username,role,plan FROM users",
    (e,r)=>res.json(r)
  );
});

// ADMIN REPORT
app.get("/report",auth,admin,(req,res)=>{
  db.all(`
    SELECT users.username, tasks.title
    FROM users
    LEFT JOIN tasks ON users.id = tasks.userId
  `,(e,r)=>res.json(r));
});

app.listen(process.env.PORT || 3000);
