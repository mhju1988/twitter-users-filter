const db = require('./database');

// Database initialization script
// This creates all tables and indexes for both SQLite and PostgreSQL

async function initializeDatabase() {
  console.log('Initializing database...');
  console.log('Using:', db.isPostgres ? 'PostgreSQL' : 'SQLite');

  try {
    // Create groups table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS groups (
        id ${db.isPostgres ? 'SERIAL' : 'INTEGER'} PRIMARY KEY ${db.isPostgres ? '' : 'AUTOINCREMENT'},
        name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create usernames table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS usernames (
        id ${db.isPostgres ? 'SERIAL' : 'INTEGER'} PRIMARY KEY ${db.isPostgres ? '' : 'AUTOINCREMENT'},
        group_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        display_name TEXT,
        category TEXT NOT NULL CHECK (category IN ('speaker', 'listener')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE${db.isPostgres ? '' : ',\n        UNIQUE(username, category)'}
      );
    `);

    // Create users table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id ${db.isPostgres ? 'SERIAL' : 'INTEGER'} PRIMARY KEY ${db.isPostgres ? '' : 'AUTOINCREMENT'},
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE,
        role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'editor', 'viewer')),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      );
    `);

    // Create videos table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS videos (
        id ${db.isPostgres ? 'SERIAL' : 'INTEGER'} PRIMARY KEY ${db.isPostgres ? '' : 'AUTOINCREMENT'},
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        path TEXT NOT NULL,
        size INTEGER,
        mime_type TEXT,
        uploaded_by INTEGER,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
      );
    `);

    console.log('Tables created successfully');

    // Create indexes
    console.log('Creating indexes...');

    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_usernames_group ON usernames(group_id)',
      'CREATE INDEX IF NOT EXISTS idx_usernames_category ON usernames(category)',
      'CREATE INDEX IF NOT EXISTS idx_usernames_username ON usernames(username)',
      'CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name)',
      'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)',
      'CREATE INDEX IF NOT EXISTS idx_videos_uploaded_by ON videos(uploaded_by)',
      'CREATE INDEX IF NOT EXISTS idx_videos_filename ON videos(filename)'
    ];

    for (const indexSql of indexes) {
      await db.exec(indexSql);
    }

    console.log('Indexes created successfully');

    // Migration: Fix usernames table schema (name->username, type->category, add display_name)
    console.log('Running migrations...');
    try {
      if (db.isPostgres) {
        // Check if usernames table has wrong schema
        const hasNameColumn = await db.get(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_name='usernames' AND column_name='name'
        `);

        if (hasNameColumn) {
          console.log('Migrating usernames table schema...');
          // Drop and recreate table with correct schema
          await db.exec('DROP TABLE IF EXISTS usernames CASCADE');
          await db.exec(`
            CREATE TABLE usernames (
              id SERIAL PRIMARY KEY,
              group_id INTEGER NOT NULL,
              username TEXT NOT NULL,
              display_name TEXT,
              category TEXT NOT NULL CHECK (category IN ('speaker', 'listener')),
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )
          `);
          await db.exec('CREATE INDEX IF NOT EXISTS idx_usernames_group ON usernames(group_id)');
          await db.exec('CREATE INDEX IF NOT EXISTS idx_usernames_category ON usernames(category)');
          await db.exec('CREATE INDEX IF NOT EXISTS idx_usernames_username ON usernames(username)');
          console.log('Usernames table schema migrated successfully');
        }
      }
    } catch (migrationError) {
      console.error('Usernames table migration warning:', migrationError.message);
    }

    // Migration: Add is_active column to users table if it doesn't exist
    try {
      if (db.isPostgres) {
        // PostgreSQL: Check if column exists and add if missing
        const columnCheck = await db.get(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_name='users' AND column_name='is_active'
        `);

        if (!columnCheck) {
          console.log('Adding is_active column to users table...');
          await db.exec('ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT true');
          // Update existing users to be active
          await db.exec('UPDATE users SET is_active = true WHERE is_active IS NULL');
          console.log('is_active column added successfully');
        }
      } else {
        // SQLite: Check if column exists
        const tableInfo = await db.all("PRAGMA table_info(users)");
        const hasIsActive = tableInfo.some(col => col.name === 'is_active');

        if (!hasIsActive) {
          console.log('Adding is_active column to users table...');
          await db.exec('ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1');
          console.log('is_active column added successfully');
        }
      }
    } catch (migrationError) {
      console.error('Migration warning:', migrationError.message);
      // Continue even if migration fails (column might already exist)
    }

    // Check if default group exists
    const groupCount = await db.get('SELECT COUNT(*) as count FROM groups');
    if (groupCount.count === 0) {
      await db.run('INSERT INTO groups (name) VALUES ($1)', ['Group 1']);
      console.log('Default group created');
    }

    console.log('Database initialization complete!');
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

// Run if called directly
if (require.main === module) {
  initializeDatabase()
    .then(() => {
      console.log('Done!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Failed:', error);
      process.exit(1);
    });
}

module.exports = { initializeDatabase };
