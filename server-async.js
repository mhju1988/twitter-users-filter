require('dotenv').config();
const express = require('express');
const db = require('./database');
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
const { initializeDatabase } = require('./init-db');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret-change-in-production';
const PORT = process.env.PORT || 3000;

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
const UPLOADS_DIR = process.env.UPLOADS_PATH || path.join(__dirname, 'uploads', 'videos');
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

// Trust proxy (required for Railway, Heroku, etc.)
app.set('trust proxy', 1);

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
    const existingUser = await db.get('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Check if this is the first user (make them admin)
    const userCount = await db.get('SELECT COUNT(*) as count FROM users', []);
    const isFirstUser = userCount.count === 0;
    const userRole = isFirstUser ? 'admin' : (role || 'viewer');

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await db.run(`
      INSERT INTO users (username, email, password, role)
      VALUES ($1, $2, $3, $4)
      RETURNING id
    `, [username, email, hashedPassword, userRole]);

    logger.info(`User registered: ${username} (${userRole})`);

    res.json({
      success: true,
      user: {
        id: result.id,
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
    const user = await db.get('SELECT * FROM users WHERE username = $1', [username]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Update last login
    await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

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
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await db.get('SELECT id, username, email, full_name, role, last_login, created_at FROM users WHERE id = $1', [req.user.id]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    logger.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// API Routes

// Get all groups with their usernames
app.get('/api/groups', async (req, res) => {
  try {
    const groups = await db.all('SELECT * FROM groups ORDER BY id ASC', []);

    const groupsWithUsernames = await Promise.all(groups.map(async (group) => {
      const speakers = await db.all(
        'SELECT username, display_name FROM usernames WHERE group_id = $1 AND category = $2 ORDER BY username ASC',
        [group.id, 'speaker']
      );

      const listeners = await db.all(
        'SELECT username, display_name FROM usernames WHERE group_id = $1 AND category = $2 ORDER BY username ASC',
        [group.id, 'listener']
      );

      return {
        id: group.id,
        name: group.name,
        speakers: speakers.map(row => ({
          username: row.username,
          displayName: row.display_name
        })),
        listeners: listeners.map(row => ({
          username: row.username,
          displayName: row.display_name
        }))
      };
    }));

    res.json(groupsWithUsernames);
  } catch (error) {
    console.error('Error fetching groups:', error);
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

// Create a new group
app.post('/api/groups', async (req, res) => {
  try {
    const { name } = req.body;

    const validation = validateGroupName(name);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const result = await db.run('INSERT INTO groups (name) VALUES ($1) RETURNING id', [validation.value]);
    logger.info(`Group created: ${validation.value} (ID: ${result.id})`);

    res.json({
      id: result.id,
      name: validation.value,
      speakers: [],
      listeners: []
    });
  } catch (error) {
    logger.error('Error creating group:', error);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// Update group name
app.put('/api/groups/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;

    const validation = validateGroupName(name);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const result = await db.run('UPDATE groups SET name = $1 WHERE id = $2', [validation.value, id]);

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

// Delete a group
app.delete('/api/groups/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Check if it's the last group
    const groupCount = await db.get('SELECT COUNT(*) as count FROM groups', []);
    if (groupCount.count <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last group' });
    }

    // Delete usernames first
    await db.run('DELETE FROM usernames WHERE group_id = $1', [id]);

    // Delete group
    const result = await db.run('DELETE FROM groups WHERE id = $1', [id]);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Group not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting group:', error);
    res.status(500).json({ error: 'Failed to delete group' });
  }
});

// Add usernames to a group
app.post('/api/groups/:id/usernames', async (req, res) => {
  try {
    const { id } = req.params;
    let { speakers, listeners } = req.body;

    // Validate arrays
    if (!Array.isArray(speakers)) speakers = [];
    if (!Array.isArray(listeners)) listeners = [];

    // Check if group exists
    const group = await db.get('SELECT * FROM groups WHERE id = $1', [id]);
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

    // Insert speakers
    for (const { username, displayName } of validSpeakers) {
      await db.run(
        'INSERT INTO usernames (group_id, username, display_name, category) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
        [id, username, displayName, 'speaker']
      );
    }

    // Insert listeners
    for (const { username, displayName } of validListeners) {
      await db.run(
        'INSERT INTO usernames (group_id, username, display_name, category) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
        [id, username, displayName, 'listener']
      );
    }

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

// Remove a username
app.delete('/api/usernames/:username/:category', async (req, res) => {
  try {
    const { username, category } = req.params;

    const result = await db.run('DELETE FROM usernames WHERE username = $1 AND category = $2', [username, category]);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Username not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error removing username:', error);
    res.status(500).json({ error: 'Failed to remove username' });
  }
});

// Check if username exists (for duplicate checking)
app.get('/api/usernames/check/:username', async (req, res) => {
  try {
    const { username } = req.params;

    const exists = await db.get('SELECT COUNT(*) as count FROM usernames WHERE LOWER(username) = LOWER($1)', [username]);

    res.json({ exists: exists.count > 0 });
  } catch (error) {
    logger.error('Error checking username:', error);
    res.status(500).json({ error: 'Failed to check username' });
  }
});

// Search usernames
app.get('/api/search', async (req, res) => {
  try {
    const { query } = req.query;

    if (!query || query.trim().length === 0) {
      return res.json({ results: [] });
    }

    const searchTerm = `%${query.trim()}%`;
    const results = await db.all(`
      SELECT u.username, u.category, g.id as group_id, g.name as group_name
      FROM usernames u
      JOIN groups g ON u.group_id = g.id
      WHERE LOWER(u.username) LIKE LOWER($1)
      ORDER BY u.username ASC
      LIMIT 50
    `, [searchTerm]);

    res.json({ results });
  } catch (error) {
    logger.error('Error searching usernames:', error);
    res.status(500).json({ error: 'Failed to search usernames' });
  }
});

// Export all data as JSON
app.get('/api/export/json', async (req, res) => {
  try {
    const groups = await db.all('SELECT * FROM groups ORDER BY id ASC', []);

    const exportData = await Promise.all(groups.map(async (group) => {
      const speakers = await db.all(
        'SELECT username, display_name FROM usernames WHERE group_id = $1 AND category = $2 ORDER BY username ASC',
        [group.id, 'speaker']
      );

      const listeners = await db.all(
        'SELECT username, display_name FROM usernames WHERE group_id = $1 AND category = $2 ORDER BY username ASC',
        [group.id, 'listener']
      );

      return {
        id: group.id,
        name: group.name,
        speakers: speakers.map(row => ({
          username: row.username,
          displayName: row.display_name
        })),
        listeners: listeners.map(row => ({
          username: row.username,
          displayName: row.display_name
        })),
        created_at: group.created_at
      };
    }));

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=speakers-listeners-export.json');
    res.json({ exportDate: new Date().toISOString(), groups: exportData });

    logger.info('Data exported as JSON');
  } catch (error) {
    logger.error('Error exporting JSON:', error);
    res.status(500).json({ error: 'Failed to export data' });
  }
});

// Export all data as CSV
app.get('/api/export/csv', async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT g.name as group_name, u.username, u.display_name, u.category
      FROM usernames u
      JOIN groups g ON u.group_id = g.id
      ORDER BY g.id, u.category, u.username
    `, []);

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

// Get statistics
app.get('/api/statistics', async (req, res) => {
  try {
    // Total counts
    const totalGroupsResult = await db.get('SELECT COUNT(*) as count FROM groups', []);
    const totalGroups = totalGroupsResult.count;

    const totalSpeakersResult = await db.get('SELECT COUNT(*) as count FROM usernames WHERE category = $1', ['speaker']);
    const totalSpeakers = totalSpeakersResult.count;

    const totalListenersResult = await db.get('SELECT COUNT(*) as count FROM usernames WHERE category = $1', ['listener']);
    const totalListeners = totalListenersResult.count;

    const totalUsers = totalSpeakers + totalListeners;

    // Average users per group
    const avgUsersPerGroup = totalGroups > 0 ? (totalUsers / totalGroups).toFixed(2) : 0;

    // Top 5 largest groups
    const topGroups = await db.all(`
      SELECT g.id, g.name, COUNT(u.id) as user_count
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      GROUP BY g.id, g.name
      ORDER BY user_count DESC
      LIMIT 5
    `, []);

    // Groups with user counts
    const groupDistribution = await db.all(`
      SELECT g.id, g.name,
             SUM(CASE WHEN u.category = 'speaker' THEN 1 ELSE 0 END) as speakers,
             SUM(CASE WHEN u.category = 'listener' THEN 1 ELSE 0 END) as listeners
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      GROUP BY g.id, g.name
      ORDER BY g.id ASC
    `, []);

    // Growth over time (last 30 days if created_at exists)
    const growthData = await db.all(`
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM usernames
      WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `, []);

    // Speaker/Listener ratio by group
    const ratioByGroup = await db.all(`
      SELECT g.name,
             SUM(CASE WHEN u.category = 'speaker' THEN 1 ELSE 0 END) as speakers,
             SUM(CASE WHEN u.category = 'listener' THEN 1 ELSE 0 END) as listeners
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      GROUP BY g.id, g.name
      HAVING SUM(CASE WHEN u.category = 'speaker' THEN 1 ELSE 0 END) > 0
         OR SUM(CASE WHEN u.category = 'listener' THEN 1 ELSE 0 END) > 0
    `, []);

    // Empty groups count
    const emptyGroupsResult = await db.get(`
      SELECT COUNT(*) as count
      FROM groups g
      LEFT JOIN usernames u ON g.id = u.group_id
      WHERE u.id IS NULL
    `, []);

    res.json({
      summary: {
        totalGroups,
        totalSpeakers,
        totalListeners,
        totalUsers,
        avgUsersPerGroup: parseFloat(avgUsersPerGroup),
        emptyGroups: emptyGroupsResult.count
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

// Import data from JSON
app.post('/api/import/json', async (req, res) => {
  try {
    const { groups, replaceExisting } = req.body;

    if (!Array.isArray(groups)) {
      return res.status(400).json({ error: 'Invalid import format: groups must be an array' });
    }

    if (replaceExisting) {
      // Clear existing data
      await db.run('DELETE FROM usernames', []);
      await db.run('DELETE FROM groups', []);
      logger.info('Cleared existing data for import');
    }

    let importedGroups = 0;
    let importedUsernames = 0;

    for (const group of groups) {
      const validation = validateGroupName(group.name);
      if (!validation.valid) {
        logger.warn(`Skipping invalid group: ${validation.error}`);
        continue;
      }

      const result = await db.run('INSERT INTO groups (name) VALUES ($1) RETURNING id', [validation.value]);
      const groupId = result.id;
      importedGroups++;

      if (Array.isArray(group.speakers)) {
        for (const item of group.speakers) {
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
            continue;
          }

          const usernameValidation = validateUsername(username);
          if (usernameValidation.valid && username.length > 0) {
            await db.run(
              'INSERT INTO usernames (group_id, username, display_name, category) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
              [groupId, username, displayName, 'speaker']
            );
            importedUsernames++;
          }
        }
      }

      if (Array.isArray(group.listeners)) {
        for (const item of group.listeners) {
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
            continue;
          }

          const usernameValidation = validateUsername(username);
          if (usernameValidation.valid && username.length > 0) {
            await db.run(
              'INSERT INTO usernames (group_id, username, display_name, category) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
              [groupId, username, displayName, 'listener']
            );
            importedUsernames++;
          }
        }
      }
    }

    logger.info(`Import completed: ${importedGroups} groups, ${importedUsernames} usernames`);

    res.json({
      success: true,
      imported: { importedGroups, importedUsernames }
    });
  } catch (error) {
    logger.error('Error importing JSON:', error);
    res.status(500).json({ error: 'Failed to import data' });
  }
});

// === VIDEO MANAGEMENT API ===

// Get all videos
app.get('/api/videos', async (req, res) => {
  try {
    const videos = await db.all('SELECT * FROM videos ORDER BY created_at DESC', []);
    res.json(videos);
  } catch (error) {
    logger.error('Error fetching videos:', error);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Search videos by title and description
app.get('/api/videos/search/:query', async (req, res) => {
  try {
    const { query } = req.params;
    const searchTerm = `%${query}%`;

    const videos = await db.all(`
      SELECT * FROM videos
      WHERE LOWER(title) LIKE LOWER($1) OR LOWER(description) LIKE LOWER($2)
      ORDER BY created_at DESC
    `, [searchTerm, searchTerm]);

    res.json(videos);
  } catch (error) {
    logger.error('Error searching videos:', error);
    res.status(500).json({ error: 'Failed to search videos' });
  }
});

// Get single video
app.get('/api/videos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const video = await db.get('SELECT * FROM videos WHERE id = $1', [id]);

    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    res.json(video);
  } catch (error) {
    logger.error('Error fetching video:', error);
    res.status(500).json({ error: 'Failed to fetch video' });
  }
});

// Upload new video
app.post('/api/videos', upload.single('video'), async (req, res) => {
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

    const result = await db.run(`
      INSERT INTO videos (title, description, recording_date, file_path, file_name, file_size, duration, mime_type, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id
    `, [
      title,
      description || null,
      recording_date || null,
      req.file.path,
      req.file.filename,
      req.file.size,
      duration ? parseInt(duration) : null,
      req.file.mimetype,
      metadata || null
    ]);

    logger.info(`Video uploaded: ${title} (ID: ${result.id})`);

    const video = await db.get('SELECT * FROM videos WHERE id = $1', [result.id]);
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

// Update video metadata
app.put('/api/videos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, recording_date, duration, metadata } = req.body;

    const video = await db.get('SELECT * FROM videos WHERE id = $1', [id]);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const result = await db.run(`
      UPDATE videos
      SET title = $1, description = $2, recording_date = $3, duration = $4, metadata = $5, updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
    `, [
      title || video.title,
      description !== undefined ? description : video.description,
      recording_date !== undefined ? recording_date : video.recording_date,
      duration !== undefined ? (duration ? parseInt(duration) : null) : video.duration,
      metadata !== undefined ? metadata : video.metadata,
      id
    ]);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    logger.info(`Video updated: ID ${id}`);
    const updatedVideo = await db.get('SELECT * FROM videos WHERE id = $1', [id]);
    res.json(updatedVideo);
  } catch (error) {
    logger.error('Error updating video:', error);
    res.status(500).json({ error: 'Failed to update video' });
  }
});

// Delete video
app.delete('/api/videos/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const video = await db.get('SELECT * FROM videos WHERE id = $1', [id]);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
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
    const result = await db.run('DELETE FROM videos WHERE id = $1', [id]);

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

// Stream video
app.get('/api/videos/:id/stream', async (req, res) => {
  try {
    const { id } = req.params;
    const video = await db.get('SELECT * FROM videos WHERE id = $1', [id]);

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
async function startServer() {
  try {
    // Initialize database
    await initializeDatabase();

    app.listen(PORT, async () => {
      console.log(`Server running on http://localhost:${PORT}`);
      console.log('Press Ctrl+C to stop the server');

      // Initialize with a default group if database is empty
      const groupCount = await db.get('SELECT COUNT(*) as count FROM groups', []);
      if (groupCount.count === 0) {
        await db.run('INSERT INTO groups (name) VALUES ($1)', ['Group 1']);
        console.log('Initialized with default group');
      }
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

// Graceful shutdown
process.on('SIGINT', async () => {
  await db.close();
  console.log('\nDatabase connection closed');
  process.exit(0);
});
