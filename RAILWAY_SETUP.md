# Railway Deployment - Quick Start Guide

## 🎉 Setup Complete!

Your project is now ready for production deployment on Railway with PostgreSQL and persistent file storage.

## 📁 New Files Created

1. **Dockerfile** - Container build instructions
2. **.dockerignore** - Files to exclude from Docker build
3. **database.js** - Universal database module (works with both SQLite and PostgreSQL)
4. **init-db.js** - Database schema initialization
5. **server-async.js** - Production server with PostgreSQL support
6. **railway.json** - Railway configuration
7. **DEPLOYMENT.md** - Comprehensive deployment guide
8. **RAILWAY_SETUP.md** - This file

## 🔄 How It Works

### Local Development (SQLite)
```bash
npm run dev
# Uses: server.js + SQLite database
```

### Production (PostgreSQL on Railway)
```bash
npm run start:prod
# Uses: server-async.js + PostgreSQL database
```

The `database.js` module automatically detects which database to use based on:
- If `DATABASE_URL` exists → Use PostgreSQL
- If `NODE_ENV=production` → Use PostgreSQL
- Otherwise → Use SQLite

## 🚀 Deployment Steps (Quick Version)

### 1. Push to GitHub
```bash
git add .
git commit -m "Add Railway deployment configuration"
git push origin main
```

### 2. Create Railway Project
1. Go to [railway.app/new](https://railway.app/new)
2. Click "Deploy from GitHub repo"
3. Select your repository
4. Railway auto-detects Dockerfile ✓

### 3. Add PostgreSQL
1. In Railway dashboard, click "+ New"
2. Select "Database" → "Add PostgreSQL"
3. Done! `DATABASE_URL` is auto-configured ✓

### 4. Add Volume for Videos
1. Select your app service
2. Go to "Settings" → "Volumes"
3. Click "+ Add Volume"
4. Mount Path: `/app/uploads`
5. Size: 1GB (or more)

### 5. Set Environment Variables
In Railway app settings → "Variables":
```env
NODE_ENV=production
JWT_SECRET=<generate-random-64-char-string>
SESSION_SECRET=<generate-different-random-64-char-string>
```

**Generate secrets:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 6. Initialize Database
After first deployment:
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and link to project
railway login
railway link

# Initialize database schema
railway run node init-db.js
```

### 7. Create Admin User
```bash
railway shell

# Then run this command in the shell:
node -e "
const bcrypt = require('bcrypt');
const db = require('./database');
(async () => {
  const hash = await bcrypt.hash('ChangeThisPassword123', 10);
  await db.run(
    'INSERT INTO users (username, password, email, role) VALUES (\$1, \$2, \$3, \$4)',
    ['admin', hash, 'admin@example.com', 'admin']
  );
  console.log('Admin user created!');
  process.exit(0);
})();
"
```

### 8. Access Your App
Railway provides a URL like: `https://your-app.railway.app`

## 📊 File Structure

```
E:\Arbeit\Xtwitter\
├── server.js              # Local development (SQLite)
├── server-async.js        # Production (PostgreSQL) ← NEW!
├── database.js            # Universal database module ← NEW!
├── init-db.js             # Database initialization ← NEW!
├── Dockerfile             # Docker build instructions ← NEW!
├── .dockerignore          # Docker ignore rules ← NEW!
├── railway.json           # Railway config ← NEW!
├── package.json           # Updated with new scripts
├── .env.example           # Updated with new variables
├── DEPLOYMENT.md          # Full deployment guide ← NEW!
└── RAILWAY_SETUP.md       # This quick start ← NEW!
```

## 🧪 Testing Locally with PostgreSQL (Optional)

Want to test PostgreSQL locally before deploying?

### 1. Install PostgreSQL locally or use Docker:
```bash
# Using Docker
docker run -d \
  --name postgres-dev \
  -e POSTGRES_PASSWORD=devpassword \
  -e POSTGRES_DB=xtwitter \
  -p 5432:5432 \
  postgres:15-alpine
```

### 2. Update your .env:
```env
DATABASE_URL=postgresql://postgres:devpassword@localhost:5432/xtwitter
NODE_ENV=development
JWT_SECRET=test-secret-key
SESSION_SECRET=test-session-key
```

### 3. Initialize and run:
```bash
npm run init-db
npm run dev:async
```

## 🔍 Troubleshooting

### "Database connection failed"
- Check PostgreSQL service is running in Railway
- Verify `DATABASE_URL` environment variable is set
- Run `railway run node init-db.js`

### "Files not persisting"
- Verify volume is mounted to `/app/uploads`
- Check volume is attached to app service

### "Authentication errors"
- Ensure `JWT_SECRET` and `SESSION_SECRET` are set
- Secrets must be 16+ characters

### "Port binding failed"
- Railway sets `PORT` automatically
- Don't hardcode port numbers

## 📝 NPM Scripts Reference

```bash
npm start              # Local dev with SQLite
npm run start:prod     # Production with PostgreSQL
npm run dev            # Local dev with nodemon (SQLite)
npm run dev:async      # Local dev with nodemon (PostgreSQL)
npm run init-db        # Initialize database schema
```

## 🔐 Security Checklist

Before going live:
- [ ] Strong `JWT_SECRET` set (64+ chars)
- [ ] Strong `SESSION_SECRET` set (64+ chars)
- [ ] Admin user created with strong password
- [ ] No `.env` file in Git
- [ ] Database backups configured
- [ ] Railway volume added for uploads
- [ ] Rate limiting enabled (default: 100 req/15min)

## 📈 What's Different?

### server.js (Local)
- Synchronous database calls
- SQLite database
- Simple, fast for development
- No async/await needed

### server-async.js (Production)
- Async/await database calls
- PostgreSQL compatible
- Production-ready
- Same features, different DB

### database.js (Universal)
- Auto-detects environment
- Provides unified API
- Works with both databases
- Transparent switching

## 🎯 Next Steps

1. **Read DEPLOYMENT.md** for comprehensive guide
2. **Push to GitHub** to trigger deployment
3. **Set up Railway project** following steps above
4. **Initialize database** with `railway run node init-db.js`
5. **Create admin user** and test
6. **Monitor logs** in Railway dashboard

## 💰 Cost Estimate

Railway pricing (approx):
- **Free tier**: $5 credit/month
- **Small app**: Usually covered by free tier
- **PostgreSQL**: ~$5/month
- **Volume (1GB)**: ~$0.25/month
- **Total**: ~$5-10/month for small/medium traffic

## 📚 Documentation

- **Full deployment guide**: See `DEPLOYMENT.md`
- **Railway docs**: [docs.railway.app](https://docs.railway.app)
- **PostgreSQL guide**: [postgresql.org/docs](https://postgresql.org/docs)

## ✅ Migration Summary

**Converted:**
- ✓ 29 API routes to async
- ✓ 80+ database calls to PostgreSQL
- ✓ Parameter binding (? → $1, $2)
- ✓ Database initialization
- ✓ File uploads to volume

**Unchanged:**
- ✓ All validation logic
- ✓ Authentication/authorization
- ✓ Business logic
- ✓ API endpoints
- ✓ Frontend code

## 🆘 Need Help?

- **Railway Discord**: [discord.gg/railway](https://discord.gg/railway)
- **Railway Docs**: [docs.railway.app](https://docs.railway.app)
- **Issues**: Create issue in your GitHub repo

---

**Ready to deploy?** Follow the 8 steps above! 🚀
