require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const app = express();
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

const sanitizeUsername = (username) => {
  // Handle common patterns like "username —" (em dash), "username -", etc.
  let sanitized = username
    .replace(/\s+[—–-]+$/g, '') // Remove space + any type of dash at the end (em dash, en dash, hyphen)
    .replace(/\s+\.$/g, '') // Remove space + dot at the end
    .trim()
    .replace(/[^\w.-]/g, ''); // Remove invalid characters (keeps alphanumeric, _, -, .)

  // Remove trailing hyphens and dots (copy-paste artifacts)
  sanitized = sanitized.replace(/[-.]+$/, '');
  // Remove leading hyphens and dots
  sanitized = sanitized.replace(/^[-.]+/, '');

  return sanitized;
};

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// API Routes

// Get all groups with their usernames
app.get('/api/groups', (req, res) => {
  try {
    const groups = db.prepare('SELECT * FROM groups ORDER BY id ASC').all();

    const groupsWithUsernames = groups.map(group => {
      const speakers = db.prepare(
        'SELECT username FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'speaker').map(row => row.username);

      const listeners = db.prepare(
        'SELECT username FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'listener').map(row => row.username);

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

// Create a new group
app.post('/api/groups', (req, res) => {
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

// Update group name
app.put('/api/groups/:id', (req, res) => {
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

// Delete a group
app.delete('/api/groups/:id', (req, res) => {
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

// Add usernames to a group
app.post('/api/groups/:id/usernames', (req, res) => {
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

    // Sanitize first, then validate usernames
    const validSpeakers = [];
    const validListeners = [];
    const errors = [];

    speakers.forEach(username => {
      const sanitized = sanitizeUsername(username);
      const validation = validateUsername(sanitized);
      if (validation.valid && sanitized.length > 0) {
        validSpeakers.push(sanitized);
      } else {
        errors.push(`Speaker "${username}": ${validation.error || 'Empty after sanitization'}`);
      }
    });

    listeners.forEach(username => {
      const sanitized = sanitizeUsername(username);
      const validation = validateUsername(sanitized);
      if (validation.valid && sanitized.length > 0) {
        validListeners.push(sanitized);
      } else {
        errors.push(`Listener "${username}": ${validation.error || 'Empty after sanitization'}`);
      }
    });

    if (validSpeakers.length === 0 && validListeners.length === 0) {
      return res.status(400).json({ error: 'No valid usernames provided', details: errors });
    }

    const insertStmt = db.prepare('INSERT OR IGNORE INTO usernames (group_id, username, category) VALUES (?, ?, ?)');

    const insertMany = db.transaction((speakers, listeners) => {
      speakers.forEach(username => {
        insertStmt.run(id, username, 'speaker');
      });

      listeners.forEach(username => {
        insertStmt.run(id, username, 'listener');
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

// Remove a username
app.delete('/api/usernames/:username/:category', (req, res) => {
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

// Check if username exists (for duplicate checking)
app.get('/api/usernames/check/:username', (req, res) => {
  try {
    const { username } = req.params;

    const exists = db.prepare('SELECT COUNT(*) as count FROM usernames WHERE LOWER(username) = LOWER(?)').get(username);

    res.json({ exists: exists.count > 0 });
  } catch (error) {
    logger.error('Error checking username:', error);
    res.status(500).json({ error: 'Failed to check username' });
  }
});

// Search usernames
app.get('/api/search', (req, res) => {
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

// Export all data as JSON
app.get('/api/export/json', (req, res) => {
  try {
    const groups = db.prepare('SELECT * FROM groups ORDER BY id ASC').all();

    const exportData = groups.map(group => {
      const speakers = db.prepare(
        'SELECT username FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'speaker').map(row => row.username);

      const listeners = db.prepare(
        'SELECT username FROM usernames WHERE group_id = ? AND category = ? ORDER BY username ASC'
      ).all(group.id, 'listener').map(row => row.username);

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

// Export all data as CSV
app.get('/api/export/csv', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT g.name as group_name, u.username, u.category
      FROM usernames u
      JOIN groups g ON u.group_id = g.id
      ORDER BY g.id, u.category, u.username
    `).all();

    let csv = 'Group Name,Username,Category\n';
    rows.forEach(row => {
      csv += `"${row.group_name}","${row.username}","${row.category}"\n`;
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

// Import data from JSON
app.post('/api/import/json', (req, res) => {
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

        const insertUsername = db.prepare('INSERT OR IGNORE INTO usernames (group_id, username, category) VALUES (?, ?, ?)');

        if (Array.isArray(group.speakers)) {
          group.speakers.forEach(username => {
            const sanitized = sanitizeUsername(username);
            const usernameValidation = validateUsername(sanitized);
            if (usernameValidation.valid && sanitized.length > 0) {
              insertUsername.run(groupId, sanitized, 'speaker');
              importedUsernames++;
            }
          });
        }

        if (Array.isArray(group.listeners)) {
          group.listeners.forEach(username => {
            const sanitized = sanitizeUsername(username);
            const usernameValidation = validateUsername(sanitized);
            if (usernameValidation.valid && sanitized.length > 0) {
              insertUsername.run(groupId, sanitized, 'listener');
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
