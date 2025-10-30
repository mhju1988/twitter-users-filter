require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret-change-in-production';
const PORT = process.env.PORT || 3000;
const DATABASE_PATH = process.env.DATABASE_PATH || './speakers_listeners.db';

// Configure logging
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Initialize database
const db = new Database(DATABASE_PATH);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS usernames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    display_name TEXT,
    category TEXT NOT NULL CHECK(category IN ('speaker', 'listener')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    UNIQUE(username, category)
  );

  -- Create indexes for better performance
  CREATE INDEX IF NOT EXISTS idx_usernames_group ON usernames(group_id);
  CREATE INDEX IF NOT EXISTS idx_usernames_username ON usernames(LOWER(username));
  CREATE INDEX IF NOT EXISTS idx_usernames_category ON usernames(category);
`);

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    role TEXT NOT NULL CHECK(role IN ('admin', 'editor', 'viewer')) DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT 1,
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
`);

// Create videos table
db.exec(`
  CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    recording_date DATE,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER,
    duration INTEGER,
    mime_type TEXT,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_videos_recording_date ON videos(recording_date);
  CREATE INDEX IF NOT EXISTS idx_videos_created_at ON videos(created_at);
`);

// Migration: Add display_name column to existing databases
try {
  const usernamesTableInfo = db.prepare("PRAGMA table_info(usernames)").all();
  const hasDisplayName = usernamesTableInfo.some(col => col.name === 'display_name');

  if (!hasDisplayName) {
    console.log('Migrating database: Adding display_name column...');
    db.exec('ALTER TABLE usernames ADD COLUMN display_name TEXT');
    console.log('display_name migration completed!');
  }
} catch (error) {
  console.error('Migration error (display_name):', error);
}

// Migration: Add created_by column to videos table
try {
  const videosTableInfo = db.prepare("PRAGMA table_info(videos)").all();
  const hasCreatedBy = videosTableInfo.some(col => col.name === 'created_by');

  if (!hasCreatedBy) {
    console.log('Migrating database: Adding created_by column to videos...');
    db.exec('ALTER TABLE videos ADD COLUMN created_by INTEGER REFERENCES users(id)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_videos_created_by ON videos(created_by)');
    console.log('created_by migration completed!');
  }
} catch (error) {
  console.error('Migration error (created_by):', error);
}

// Migration: Ensure users table has expected columns
try {
  const usersTableInfo = db.prepare("PRAGMA table_info(users)").all();
  const hasColumn = (name) => usersTableInfo.some(col => col.name === name);

  if (!hasColumn('full_name')) {
    console.log('Migrating database: Adding full_name to users...');
    db.exec('ALTER TABLE users ADD COLUMN full_name TEXT');
  }
  if (!hasColumn('is_active')) {
    console.log('Migrating database: Adding is_active to users...');
    db.exec('ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1');
  }
  if (!hasColumn('last_login')) {
    console.log('Migrating database: Adding last_login to users...');
    db.exec('ALTER TABLE users ADD COLUMN last_login DATETIME');
  }
  if (!hasColumn('created_at')) {
    console.log('Migrating database: Adding created_at to users...');
    db.exec('ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP');
  }
  if (!hasColumn('updated_at')) {
    console.log('Migrating database: Adding updated_at to users...');
    db.exec('ALTER TABLE users ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP');
  }
} catch (error) {
  console.error('Migration error (users):', error);
}

// Validation functions
const validateUsername = (username) => {
  if (!username || typeof username !== 'string') return { valid: false, error: 'Username must be a string' };
  if (username.length === 0) return { valid: false, error: 'Username cannot be empty' };
  if (username.length > 50) return { valid: false, error: 'Username cannot exceed 50 characters' };
  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) return { valid: false, error: 'Username can only contain letters, numbers, underscores, dots, and hyphens' };
  return { valid: true };
};

const validateGroupName = (name) => {
  if (!name || typeof name !== 'string') return { valid: false, error: 'Group name must be a string' };
  const trimmed = name.trim();
  if (trimmed.length === 0) return { valid: false, error: 'Group name cannot be empty' };
  if (trimmed.length > 100) return { valid: false, error: 'Group name cannot exceed 100 characters' };
  return { valid: true, value: trimmed };
};

const parseUsernameAndDisplay = (input) => {
  // Parse format: "@username — Display Name" or just "@username"
  // Also handles em dash (—), en dash (–), and regular hyphen (-)

  // Remove leading @ if present
  let cleaned = input.replace(/^@/, '').trim();

  // Check for display name separator (em dash, en dash, or hyphen with spaces)
  const separatorRegex = /\s+[—–-]\s+/;
  const parts = cleaned.split(separatorRegex);

  let username = parts[0].trim();
  let displayName = parts.length > 1 ? parts.slice(1).join(' ').trim() : '';

  // Sanitize username (keep only valid characters)
  username = username
    .replace(/[^\w.-]/g, '') // Remove invalid characters (keeps alphanumeric, _, -, .)
    .replace(/[-.]+$/, '') // Remove trailing hyphens/dots
    .replace(/^[-.]+/, ''); // Remove leading hyphens/dots

  // Display name can have spaces and more characters, but sanitize HTML special chars
  if (displayName) {
    displayName = displayName
      .replace(/[<>]/g, '') // Remove HTML tags
      .slice(0, 100); // Max 100 characters for display name
  }

  return { username, displayName: displayName || null };
};

// Ensure uploads directory exists
const UPLOADS_DIR = path.join(__dirname, 'uploads', 'videos');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Configure multer for video uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 500 * 1024 * 1024 // 500MB max file size
  },
  fileFilter: (req, file, cb) => {
    // Accept video files only
    const allowedMimes = ['video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo', 'video/x-matroska', 'video/webm'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only video files are allowed.'));
    }
  }
});

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// === AUTHENTICATION MIDDLEWARE ===

// Verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

// Check user role
const authorizeRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
    }

    next();
  };
};

// === AUTHENTICATION API ===

// Register new user (admin only in production, open for first user)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, full_name, role } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if user already exists
    const existingUser = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Check if this is the first user (make them admin)
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    const isFirstUser = userCount.count === 0;
    const userRole = isFirstUser ? 'admin' : (role || 'viewer');

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Create user
    const result = db.prepare(`
      INSERT INTO users (username, email, password_hash, full_name, role)
      VALUES (?, ?, ?, ?, ?)
    `).run(username, email, password_hash, full_name || null, userRole);

    logger.info(`User registered: ${username} (${userRole})`);

    res.json({
      success: true,
      user: {
        id: result.lastInsertRowid,
        username,
        email,
        role: userRole
      }
    });
  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Update last login
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    logger.info(`User logged in: ${username}`);

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      },
      token
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  req.session.destroy();
  res.json({ success: true, message: 'Logged out successfully' });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  try {
    const user = db.prepare('SELECT id, username, email, full_name, role, last_login, created_at FROM users WHERE id = ?').get(req.user.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    logger.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// === USER MANAGEMENT API (Admin Only) ===

// Get all users (admin only)
app.get('/api/users', authenticateToken, authorizeRole('admin'), (req, res) => {
  try {
    const users = db.prepare(`
      SELECT id, username, email, full_name, role, is_active, last_login, created_at
      FROM users
      ORDER BY created_at ASC
    `).all();

    res.json(users);
  } catch (error) {
    logger.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update user role (admin only)
app.put('/api/users/:id/role', authenticateToken, authorizeRole('admin'), (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    // Validate role
    const validRoles = ['admin', 'editor', 'viewer'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Must be: admin, editor, or viewer' });
    }

    // Prevent changing own role
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'You cannot change your own role' });
    }

    // Check if user exists
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update role
    const result = db.prepare('UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(role, id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info(`User role updated: ID ${id}, new role: ${role}`);
    res.json({ success: true, message: 'User role updated successfully' });
  } catch (error) {
    logger.error('Error updating user role:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// Toggle user active status (admin only)
app.put('/api/users/:id/status', authenticateToken, authorizeRole('admin'), (req, res) => {
  try {
    const { id } = req.params;
    const { is_active } = req.body;

    // Prevent deactivating own account
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'You cannot deactivate your own account' });
    }

    // Check if user exists
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update status
    const result = db.prepare('UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(is_active ? 1 : 0, id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info(`User status updated: ID ${id}, active: ${is_active}`);
    res.json({ success: true, message: 'User status updated successfully' });
  } catch (error) {
    logger.error('Error updating user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  try {
    const { id } = req.params;

    // Prevent deleting own account
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    // Check if user exists
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if it's the last admin
    if (user.role === 'admin') {
      const adminCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get('admin');
      if (adminCount.count <= 1) {
        return res.status(400).json({ error: 'Cannot delete the last admin user' });
      }
    }

    // Delete user
    const result = db.prepare('DELETE FROM users WHERE id = ?').run(id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info(`User deleted: ID ${id} (${user.username})`);
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    logger.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// API Routes

// Get all groups with their usernames (requires authentication)
app.get('/api/groups', authenticateToken, (req, res) => {
  try {
    const groups = db.prepare('SELECT * FROM groups ORDER BY id ASC').all();

    const groupsWithUsernames = groups.map(group => {
      const speakers = db.prepare(
        'SELECT username, display_name FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'speaker').map(row => ({
        username: row.username,
        displayName: row.display_name
      }));

      const listeners = db.prepare(
        'SELECT username, display_name FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'listener').map(row => ({
        username: row.username,
        displayName: row.display_name
      }));

      return {
        id: group.id,
        name: group.name,
        speakers,
        listeners
      };
    });

    res.json(groupsWithUsernames);
  } catch (error) {
    console.error('Error fetching groups:', error);
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

// Create a new group (editor+ only)
app.post('/api/groups', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const { name } = req.body;

    const validation = validateGroupName(name);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const result = db.prepare('INSERT INTO groups (name) VALUES (?)').run(validation.value);
    logger.info(`Group created: ${validation.value} (ID: ${result.lastInsertRowid})`);

    res.json({
      id: result.lastInsertRowid,
      name: validation.value,
      speakers: [],
      listeners: []
    });
  } catch (error) {
    logger.error('Error creating group:', error);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// Update group name (editor+ only)
app.put('/api/groups/:id', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;

    const validation = validateGroupName(name);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const result = db.prepare('UPDATE groups SET name = ? WHERE id = ?').run(validation.value, id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Group not found' });
    }

    logger.info(`Group updated: ID ${id}, new name: ${validation.value}`);
    res.json({ success: true });
  } catch (error) {
    logger.error('Error updating group:', error);
    res.status(500).json({ error: 'Failed to update group' });
  }
});

// Delete a group (admin only)
app.delete('/api/groups/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  try {
    const { id } = req.params;

    // Check if it's the last group
    const groupCount = db.prepare('SELECT COUNT(*) as count FROM groups').get();
    if (groupCount.count <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last group' });
    }

    // Delete usernames first
    db.prepare('DELETE FROM usernames WHERE group_id = ?').run(id);

    // Delete group
    const result = db.prepare('DELETE FROM groups WHERE id = ?').run(id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Group not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting group:', error);
    res.status(500).json({ error: 'Failed to delete group' });
  }
});

// Add usernames to a group (editor+ only)
app.post('/api/groups/:id/usernames', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const { id } = req.params;
    let { speakers, listeners } = req.body;

    // Validate arrays
    if (!Array.isArray(speakers)) speakers = [];
    if (!Array.isArray(listeners)) listeners = [];

    // Check if group exists
    const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(id);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    // Parse and validate usernames with display names
    const validSpeakers = [];
    const validListeners = [];
    const errors = [];

    speakers.forEach(input => {
      const { username, displayName } = parseUsernameAndDisplay(input);
      const validation = validateUsername(username);
      if (validation.valid && username.length > 0) {
        validSpeakers.push({ username, displayName });
      } else {
        errors.push(`Speaker "${input}": ${validation.error || 'Empty after sanitization'}`);
      }
    });

    listeners.forEach(input => {
      const { username, displayName } = parseUsernameAndDisplay(input);
      const validation = validateUsername(username);
      if (validation.valid && username.length > 0) {
        validListeners.push({ username, displayName });
      } else {
        errors.push(`Listener "${input}": ${validation.error || 'Empty after sanitization'}`);
      }
    });

    if (validSpeakers.length === 0 && validListeners.length === 0) {
      return res.status(400).json({ error: 'No valid usernames provided', details: errors });
    }

    const insertStmt = db.prepare('INSERT OR IGNORE INTO usernames (group_id, username, display_name, category) VALUES (?, ?, ?, ?)');

    const insertMany = db.transaction((speakers, listeners) => {
      speakers.forEach(({ username, displayName }) => {
        insertStmt.run(id, username, displayName, 'speaker');
      });

      listeners.forEach(({ username, displayName }) => {
        insertStmt.run(id, username, displayName, 'listener');
      });
    });

    insertMany(validSpeakers, validListeners);

    logger.info(`Added ${validSpeakers.length} speakers and ${validListeners.length} listeners to group ${id}`);

    const response = { success: true, added: { speakers: validSpeakers.length, listeners: validListeners.length } };
    if (errors.length > 0) {
      response.warnings = errors;
    }

    res.json(response);
  } catch (error) {
    logger.error('Error adding usernames:', error);
    res.status(500).json({ error: 'Failed to add usernames' });
  }
});

// Remove a username (editor+ only)
app.delete('/api/usernames/:username/:category', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const { username, category } = req.params;

    const result = db.prepare('DELETE FROM usernames WHERE username = ? AND category = ?').run(username, category);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Username not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error removing username:', error);
    res.status(500).json({ error: 'Failed to remove username' });
  }
});

// Check if username exists (for duplicate checking) (requires authentication)
app.get('/api/usernames/check/:username', authenticateToken, (req, res) => {
  try {
    const { username } = req.params;

    const exists = db.prepare('SELECT COUNT(*) as count FROM usernames WHERE LOWER(username) = LOWER(?)').get(username);

    res.json({ exists: exists.count > 0 });
  } catch (error) {
    logger.error('Error checking username:', error);
    res.status(500).json({ error: 'Failed to check username' });
  }
});

// Search usernames (requires authentication)
app.get('/api/search', authenticateToken, (req, res) => {
  try {
    const { query } = req.query;

    if (!query || query.trim().length === 0) {
      return res.json({ results: [] });
    }

    const searchTerm = `%${query.trim()}%`;
    const results = db.prepare(`
      SELECT u.username, u.category, g.id as group_id, g.name as group_name
      FROM usernames u
      JOIN groups g ON u.group_id = g.id
      WHERE LOWER(u.username) LIKE LOWER(?)
      ORDER BY u.username ASC
      LIMIT 50
    `).all(searchTerm);

    res.json({ results });
  } catch (error) {
    logger.error('Error searching usernames:', error);
    res.status(500).json({ error: 'Failed to search usernames' });
  }
});

// Export all data as JSON (editor+ only)
app.get('/api/export/json', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const groups = db.prepare('SELECT * FROM groups ORDER BY id ASC').all();

    const exportData = groups.map(group => {
      const speakers = db.prepare(
        'SELECT username, display_name FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'speaker').map(row => ({
        username: row.username,
        displayName: row.display_name
      }));

      const listeners = db.prepare(
        'SELECT username, display_name FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'listener').map(row => ({
        username: row.username,
        displayName: row.display_name
      }));

      return {
        id: group.id,
        name: group.name,
        speakers,
        listeners,
        created_at: group.created_at
      };
    });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=speakers-listeners-export.json');
    res.json({ exportDate: new Date().toISOString(), groups: exportData });

    logger.info('Data exported as JSON');
  } catch (error) {
    logger.error('Error exporting JSON:', error);
    res.status(500).json({ error: 'Failed to export data' });
  }
});

// Export all data as CSV (editor+ only)
app.get('/api/export/csv', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT g.name as group_name, u.username, u.display_name, u.category
      FROM usernames u
      JOIN groups g ON u.group_id = g.id
      ORDER BY g.id, u.category, u.username
    `).all();

    let csv = 'Group Name,Username,Display Name,Category\n';
    rows.forEach(row => {
      csv += `"${row.group_name}","${row.username}","${row.display_name || ''}","${row.category}"\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=speakers-listeners-export.csv');
    res.send(csv);

    logger.info('Data exported as CSV');
  } catch (error) {
    logger.error('Error exporting CSV:', error);
    res.status(500).json({ error: 'Failed to export data' });
  }
});

// Get statistics (requires authentication)
app.get('/api/statistics', authenticateToken, (req, res) => {
  try {
    // Total counts
    const totalGroups = db.prepare('SELECT COUNT(*) as count FROM groups').get().count;
    const totalSpeakers = db.prepare('SELECT COUNT(*) as count FROM usernames WHERE category = ?').get('speaker').count;
    const totalListeners = db.prepare('SELECT COUNT(*) as count FROM usernames WHERE category = ?').get('listener').count;
    const totalUsers = Number(totalSpeakers) + Number(totalListeners);

    // Average users per group
    const avgUsersPerGroup = totalGroups > 0 ? (totalUsers / totalGroups).toFixed(2) : 0;

    // Top 5 largest groups
    const topGroups = db.prepare(`
      SELECT g.id, g.name, COUNT(u.id) as user_count
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      GROUP BY g.id
      ORDER BY user_count DESC
      LIMIT 5
    `).all();

    // Groups with user counts
    const groupDistribution = db.prepare(`
      SELECT g.id, g.name,
             SUM(CASE WHEN u.category = 'speaker' THEN 1 ELSE 0 END) as speakers,
             SUM(CASE WHEN u.category = 'listener' THEN 1 ELSE 0 END) as listeners
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      GROUP BY g.id
      ORDER BY g.id ASC
    `).all();

    // Growth over time (last 30 days if created_at exists)
    const growthData = db.prepare(`
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM usernames
      WHERE created_at >= date('now', '-30 days')
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `).all();

    // Speaker/Listener ratio by group
    const ratioByGroup = db.prepare(`
      SELECT g.name,
             SUM(CASE WHEN u.category = 'speaker' THEN 1 ELSE 0 END) as speakers,
             SUM(CASE WHEN u.category = 'listener' THEN 1 ELSE 0 END) as listeners
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      GROUP BY g.id
      HAVING speakers > 0 OR listeners > 0
    `).all();

    // Empty groups count
    const emptyGroups = db.prepare(`
      SELECT COUNT(*) as count
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      WHERE u.id IS NULL
    `).get().count;

    res.json({
      summary: {
        totalGroups,
        totalSpeakers,
        totalListeners,
        totalUsers,
        avgUsersPerGroup: parseFloat(avgUsersPerGroup),
        emptyGroups
      },
      topGroups,
      groupDistribution,
      growthData,
      ratioByGroup
    });

    logger.info('Statistics retrieved');
  } catch (error) {
    logger.error('Error getting statistics:', error);
    res.status(500).json({ error: 'Failed to retrieve statistics' });
  }
});

// Import data from JSON (editor+ only)
app.post('/api/import/json', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const { groups, replaceExisting } = req.body;

    if (!Array.isArray(groups)) {
      return res.status(400).json({ error: 'Invalid import format: groups must be an array' });
    }

    const importTransaction = db.transaction(() => {
      if (replaceExisting) {
        // Clear existing data
        db.prepare('DELETE FROM usernames').run();
        db.prepare('DELETE FROM groups').run();
        logger.info('Cleared existing data for import');
      }

      let importedGroups = 0;
      let importedUsernames = 0;

      groups.forEach(group => {
        const validation = validateGroupName(group.name);
        if (!validation.valid) {
          logger.warn(`Skipping invalid group: ${validation.error}`);
          return;
        }

        const result = db.prepare('INSERT INTO groups (name) VALUES (?)').run(validation.value);
        const groupId = result.lastInsertRowid;
        importedGroups++;

        const insertUsername = db.prepare('INSERT OR IGNORE INTO usernames (group_id, username, display_name, category) VALUES (?, ?, ?, ?)');

        if (Array.isArray(group.speakers)) {
          group.speakers.forEach(item => {
            // Handle both old format (string) and new format (object)
            let username, displayName;
            if (typeof item === 'string') {
              const parsed = parseUsernameAndDisplay(item);
              username = parsed.username;
              displayName = parsed.displayName;
            } else if (typeof item === 'object' && item.username) {
              username = item.username;
              displayName = item.displayName || null;
            } else {
              return;
            }

            const usernameValidation = validateUsername(username);
            if (usernameValidation.valid && username.length > 0) {
              insertUsername.run(groupId, username, displayName, 'speaker');
              importedUsernames++;
            }
          });
        }

        if (Array.isArray(group.listeners)) {
          group.listeners.forEach(item => {
            // Handle both old format (string) and new format (object)
            let username, displayName;
            if (typeof item === 'string') {
              const parsed = parseUsernameAndDisplay(item);
              username = parsed.username;
              displayName = parsed.displayName;
            } else if (typeof item === 'object' && item.username) {
              username = item.username;
              displayName = item.displayName || null;
            } else {
              return;
            }

            const usernameValidation = validateUsername(username);
            if (usernameValidation.valid && username.length > 0) {
              insertUsername.run(groupId, username, displayName, 'listener');
              importedUsernames++;
            }
          });
        }
      });

      return { importedGroups, importedUsernames };
    });

    const result = importTransaction();
    logger.info(`Import completed: ${result.importedGroups} groups, ${result.importedUsernames} usernames`);

    res.json({
      success: true,
      imported: result
    });
  } catch (error) {
    logger.error('Error importing JSON:', error);
    res.status(500).json({ error: 'Failed to import data' });
  }
});

// === VIDEO MANAGEMENT API ===

// Get all videos (requires authentication)
app.get('/api/videos', authenticateToken, (req, res) => {
  try {
    const videos = db.prepare(`
      SELECT v.*, u.username as creator_username, u.full_name as creator_name
      FROM videos v
      LEFT JOIN users u ON v.created_by = u.id
      ORDER BY v.created_at DESC
    `).all();
    res.json(videos);
  } catch (error) {
    logger.error('Error fetching videos:', error);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Search videos by title and description (requires authentication)
app.get('/api/videos/search/:query', authenticateToken, (req, res) => {
  try {
    const { query } = req.params;
    const searchTerm = `%${query}%`;

    const videos = db.prepare(`
      SELECT v.*, u.username as creator_username, u.full_name as creator_name
      FROM videos v
      LEFT JOIN users u ON v.created_by = u.id
      WHERE LOWER(v.title) LIKE LOWER(?) OR LOWER(v.description) LIKE LOWER(?)
      ORDER BY v.created_at DESC
    `).all(searchTerm, searchTerm);

    res.json(videos);
  } catch (error) {
    logger.error('Error searching videos:', error);
    res.status(500).json({ error: 'Failed to search videos' });
  }
});

// Get single video (requires authentication)
app.get('/api/videos/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const video = db.prepare(`
      SELECT v.*, u.username as creator_username, u.full_name as creator_name
      FROM videos v
      LEFT JOIN users u ON v.created_by = u.id
      WHERE v.id = ?
    `).get(id);

    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    res.json(video);
  } catch (error) {
    logger.error('Error fetching video:', error);
    res.status(500).json({ error: 'Failed to fetch video' });
  }
});

// Upload new video (editor+ only)
app.post('/api/videos', authenticateToken, authorizeRole('admin', 'editor'), upload.single('video'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No video file uploaded' });
    }

    const { title, description, recording_date, duration, metadata } = req.body;

    if (!title) {
      // Delete uploaded file if validation fails
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Title is required' });
    }

    const result = db.prepare(`
      INSERT INTO videos (title, description, recording_date, file_path, file_name, file_size, duration, mime_type, metadata, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      title,
      description || null,
      recording_date || null,
      req.file.path,
      req.file.filename,
      req.file.size,
      duration ? parseInt(duration) : null,
      req.file.mimetype,
      metadata || null,
      req.user.id
    );

    logger.info(`Video uploaded: ${title} (ID: ${result.lastInsertRowid})`);

    const video = db.prepare('SELECT * FROM videos WHERE id = ?').get(result.lastInsertRowid);
    res.json(video);
  } catch (error) {
    logger.error('Error uploading video:', error);
    // Clean up file if database insert fails
    if (req.file) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (e) {
        logger.error('Error deleting file:', e);
      }
    }
    res.status(500).json({ error: 'Failed to upload video' });
  }
});

// Update video metadata (editor+ only, editors can only edit own videos)
app.put('/api/videos/:id', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, recording_date, duration, metadata } = req.body;

    const video = db.prepare('SELECT * FROM videos WHERE id = ?').get(id);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    // Check if user owns the video (editors can only edit their own)
    if (req.user.role !== 'admin' && video.created_by !== req.user.id) {
      return res.status(403).json({ error: 'Access denied. You can only edit your own videos.' });
    }

    const result = db.prepare(`
      UPDATE videos
      SET title = ?, description = ?, recording_date = ?, duration = ?, metadata = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      title || video.title,
      description !== undefined ? description : video.description,
      recording_date !== undefined ? recording_date : video.recording_date,
      duration !== undefined ? (duration ? parseInt(duration) : null) : video.duration,
      metadata !== undefined ? metadata : video.metadata,
      id
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    logger.info(`Video updated: ID ${id}`);
    const updatedVideo = db.prepare('SELECT * FROM videos WHERE id = ?').get(id);
    res.json(updatedVideo);
  } catch (error) {
    logger.error('Error updating video:', error);
    res.status(500).json({ error: 'Failed to update video' });
  }
});

// Delete video (editor+ only, editors can only delete own videos)
app.delete('/api/videos/:id', authenticateToken, authorizeRole('admin', 'editor'), (req, res) => {
  try {
    const { id } = req.params;

    const video = db.prepare('SELECT * FROM videos WHERE id = ?').get(id);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    // Check if user owns the video (editors can only delete their own)
    if (req.user.role !== 'admin' && video.created_by !== req.user.id) {
      return res.status(403).json({ error: 'Access denied. You can only delete your own videos.' });
    }

    // Delete file from disk
    try {
      if (fs.existsSync(video.file_path)) {
        fs.unlinkSync(video.file_path);
      }
    } catch (fileError) {
      logger.error('Error deleting video file:', fileError);
    }

    // Delete from database
    const result = db.prepare('DELETE FROM videos WHERE id = ?').run(id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    logger.info(`Video deleted: ID ${id}`);
    res.json({ success: true });
  } catch (error) {
    logger.error('Error deleting video:', error);
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// Stream video (requires authentication)
app.get('/api/videos/:id/stream', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const video = db.prepare('SELECT * FROM videos WHERE id = ?').get(id);

    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    if (!fs.existsSync(video.file_path)) {
      return res.status(404).json({ error: 'Video file not found' });
    }

    const stat = fs.statSync(video.file_path);
    const fileSize = stat.size;
    const range = req.headers.range;

    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunksize = (end - start) + 1;
      const file = fs.createReadStream(video.file_path, { start, end });
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': video.mime_type || 'video/mp4',
      };
      res.writeHead(206, head);
      file.pipe(res);
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': video.mime_type || 'video/mp4',
      };
      res.writeHead(200, head);
      fs.createReadStream(video.file_path).pipe(res);
    }
  } catch (error) {
    logger.error('Error streaming video:', error);
    res.status(500).json({ error: 'Failed to stream video' });
  }
});

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop the server');

  // Initialize with a default group if database is empty
  const groupCount = db.prepare('SELECT COUNT(*) as count FROM groups').get();
  if (groupCount.count === 0) {
    db.prepare('INSERT INTO groups (name) VALUES (?)').run('Group 1');
    console.log('Initialized with default group');
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close();
  console.log('\nDatabase connection closed');
  process.exit(0);
});
