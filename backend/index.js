const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const app = express();
const PORT = 3001;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your_jwt_secret'; // Change this in production

// Middleware
app.use(cors());
app.use(express.json());

// SQLite DB setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Create tables if not exist
const userTable = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);`;
const articleTable = `CREATE TABLE IF NOT EXISTS articles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  author_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(author_id) REFERENCES users(id)
);`;
db.run(userTable);
db.run(articleTable);

app.get('/', (req, res) => {
  res.send('API is running');
});

// User Registration
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ message: 'Username already exists' });
        }
        return res.status(500).json({ message: 'Error registering user' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

// User Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ message: 'Error fetching user' });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ message: 'Error comparing passwords' });
      if (!result) return res.status(401).json({ message: 'Invalid credentials' });
      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    });
  });
});

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Create Article (protected)
app.post('/api/articles', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ message: 'Title and content required' });
  }
  db.run(
    'INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)',
    [title, content, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ message: 'Error creating article' });
      res.status(201).json({ id: this.lastID, title, content, author_id: req.user.id });
    }
  );
});

// List All Articles (public)
app.get('/api/articles', (req, res) => {
  db.all(
    'SELECT articles.id, title, content, username as author, created_at FROM articles JOIN users ON articles.author_id = users.id ORDER BY created_at DESC',
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Error fetching articles' });
      res.json(rows);
    }
  );
});

// Get Single Article by ID (public)
app.get('/api/articles/:id', (req, res) => {
  db.get(
    'SELECT articles.id, title, content, username as author, created_at FROM articles JOIN users ON articles.author_id = users.id WHERE articles.id = ?',
    [req.params.id],
    (err, row) => {
      if (err) return res.status(500).json({ message: 'Error fetching article' });
      if (!row) return res.status(404).json({ message: 'Article not found' });
      res.json(row);
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
}); 