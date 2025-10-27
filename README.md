# Speakers & Listeners Manager

A full-stack web application for managing speakers and listeners with intelligent text parsing, group management, persistent data storage, and enterprise-grade security features.

## ✨ Features

### Core Functionality
- **Intelligent Text Parsing**: Automatically detects "Speakers:" and "Listeners:" headers and categorizes usernames
- **Duplicate Filtering**: Prevents duplicate usernames across all groups
- **Group Management**: Create, rename, and delete groups with full CRUD operations
- **Persistent Storage**: All data stored in SQLite database with transactions

### New in v2.0
- **🔍 Search**: Real-time username search across all groups
- **📥 Export**: Download your data as JSON or CSV
- **📤 Import**: Restore from backups or migrate data
- **🔔 Toast Notifications**: Modern, non-intrusive feedback system
- **🔐 Input Validation**: Comprehensive server-side validation
- **🛡️ Rate Limiting**: Protection against abuse (100 req/15min)
- **⚡ Database Indexing**: Optimized queries for better performance
- **📝 Logging**: Professional logging with Winston
- **⚙️ Environment Config**: Configurable via .env file

## Prerequisites

- Node.js (v14 or higher)
- npm (comes with Node.js)

## Installation

1. Open a terminal in the project directory

2. Install dependencies:
```bash
npm install
```

## Running the Application

1. Start the server:
```bash
npm start
```

For development with auto-restart on file changes:
```bash
npm run dev
```

2. Open your browser and navigate to:
```
http://localhost:3000
```

## Usage

### Adding Usernames

1. Paste text into the input field with the following format:
```
Speakers:
username1
username2

Listeners:
username3
username4
```

2. Click "Add to Current Group" to add usernames to the last group
3. Duplicates are automatically filtered out

### Managing Groups

- **Create**: Click "Create New Group" to add a new group
- **Rename**: Click on any group name to edit it
- **Delete**: Click the "Delete" button on a group (must have at least one group)

### Removing Usernames

- Click the × symbol next to any username to remove it

### Searching for Users

1. Type any part of a username in the search bar at the top
2. Results appear in real-time as you type
3. Click on a search result to jump to that group with a highlight animation

### Exporting Your Data

**JSON Export** (for backups and re-importing):
1. Click "Export JSON" in the toolbar
2. File downloads automatically with timestamp
3. Contains complete data structure

**CSV Export** (for spreadsheets):
1. Click "Export CSV" in the toolbar
2. Opens in Excel, Google Sheets, or any CSV reader
3. Format: Group Name, Username, Category

### Importing Data

1. Click "Import" in the toolbar
2. Select a JSON file (previously exported)
3. Choose mode:
   - **Merge**: Add to existing data
   - **Replace**: Delete all and import (⚠️ Warning shown)
4. Click "Import" to process
5. Get confirmation with import statistics

## API Endpoints

### Groups
- `GET /api/groups` - Get all groups with usernames
- `POST /api/groups` - Create a new group
- `PUT /api/groups/:id` - Update group name
- `DELETE /api/groups/:id` - Delete a group

### Usernames
- `POST /api/groups/:id/usernames` - Add usernames to a group
- `DELETE /api/usernames/:username/:category` - Remove a username
- `GET /api/usernames/check/:username` - Check if username exists

### Search & Data Management
- `GET /api/search?query=<term>` - Search usernames (returns up to 50 results)
- `GET /api/export/json` - Export all data as JSON
- `GET /api/export/csv` - Export all data as CSV
- `POST /api/import/json` - Import data from JSON

## Database

The application uses SQLite for data storage. The database file `speakers_listeners.db` is automatically created in the project directory on first run.

### Database Schema

**groups** table:
- id (INTEGER, PRIMARY KEY)
- name (TEXT)
- created_at (DATETIME)

**usernames** table:
- id (INTEGER, PRIMARY KEY)
- group_id (INTEGER, FOREIGN KEY)
- username (TEXT)
- category (TEXT: 'speaker' or 'listener')
- created_at (DATETIME)

## Project Structure

```
.
├── server.js              # Express server and API endpoints
├── package.json           # Node.js dependencies and scripts
├── public/
│   └── index.html        # Frontend application
├── speakers_listeners.db  # SQLite database (auto-generated)
└── README.md             # This file
```

## Configuration

The application uses environment variables for configuration. Copy `.env.example` to `.env` and modify as needed:

```env
# Server Configuration
PORT=3000                           # Server port
NODE_ENV=development                # Environment (development/production)

# Database Configuration
DATABASE_PATH=./speakers_listeners.db  # Database file location

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000         # Time window (15 minutes)
RATE_LIMIT_MAX_REQUESTS=100         # Max requests per window
```

## Security Features

- **Input Validation**: All usernames and group names validated
  - Usernames: Max 50 chars, alphanumeric + `_.-` only
  - Group names: Max 100 chars
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **XSS Protection**: All user content HTML-escaped
- **SQL Injection Protection**: Prepared statements used throughout
- **Database Integrity**: Foreign key constraints and transactions
- **Error Handling**: Comprehensive error catching with logging

## Technologies Used

- **Backend**: Node.js, Express, better-sqlite3, Winston, dotenv
- **Frontend**: HTML, CSS, JavaScript (Vanilla)
- **Database**: SQLite with indexes
- **Security**: express-rate-limit, input validation

## Logging

The application logs to multiple destinations:
- `error.log` - Error-level logs only
- `combined.log` - All logs (info, debug, error)
- Console - Development output

## Notes

- The server runs on port 3000 by default (configurable via `.env`)
- Data persists across server restarts in SQLite database
- The application initializes with one default group if the database is empty
- All API routes are rate-limited for security
- Database queries use indexes for optimal performance
