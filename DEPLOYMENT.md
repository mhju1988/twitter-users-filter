# Deployment Guide - Railway

This guide explains how to deploy the Speakers & Listeners Manager to Railway with PostgreSQL and persistent file storage.

## Prerequisites

1. **Railway Account**: Sign up at [railway.app](https://railway.app)
2. **GitHub Account**: Your code should be in a GitHub repository
3. **Railway CLI** (optional): Install with `npm install -g @railway/cli`

## Architecture Overview

**Production Setup:**
- **App Hosting**: Railway (Docker container)
- **Database**: Railway PostgreSQL (managed service)
- **File Storage**: Railway Volume (persistent storage for videos)

## Step-by-Step Deployment

### 1. Prepare Your Code

Ensure all changes are committed and pushed to GitHub:

```bash
git add .
git commit -m "Prepare for Railway deployment"
git push origin main
```

### 2. Create Railway Project

1. Go to [railway.app/new](https://railway.app/new)
2. Click **"Deploy from GitHub repo"**
3. Select your repository
4. Railway will detect the Dockerfile automatically

### 3. Add PostgreSQL Database

1. In your Railway project dashboard, click **"+ New"**
2. Select **"Database"** → **"Add PostgreSQL"**
3. Railway will automatically:
   - Create a PostgreSQL instance
   - Generate `DATABASE_URL` environment variable
   - Link it to your app

### 4. Add Volume for File Uploads

1. In your Railway project, select your app service
2. Go to **"Settings"** tab
3. Scroll to **"Volumes"** section
4. Click **"+ Add Volume"**
5. Configure:
   - **Mount Path**: `/app/uploads`
   - **Size**: 1GB (or more based on your needs)
6. Click **"Add"**

### 5. Configure Environment Variables

In your Railway app settings, go to **"Variables"** tab and add:

```env
NODE_ENV=production
JWT_SECRET=<generate-a-strong-random-string>
SESSION_SECRET=<generate-a-different-strong-random-string>
PORT=3000
```

**Generate Secrets:**
```bash
# Generate random secrets (run these commands locally)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Note:** Railway automatically provides:
- `DATABASE_URL` (from PostgreSQL service)
- `PORT` (usually 3000, but Railway might override)

### 6. Initialize Database

After first deployment, you need to create the database schema:

**Option A: Using Railway CLI**
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Link to your project
railway link

# Run database initialization
railway run node init-db.js
```

**Option B: Using Railway Dashboard**
1. Go to your app service
2. Click on **"Deployments"** tab
3. Find the latest deployment
4. Click **"View Logs"**
5. Look for any database errors
6. If needed, you can run commands via the Railway shell (Settings → "Shell")

### 7. Deploy

Railway automatically deploys when you push to GitHub.

**Manual Redeploy:**
1. Go to your app service in Railway
2. Click **"Deployments"** tab
3. Click **"Redeploy"** on the latest deployment

### 8. Verify Deployment

1. Railway will provide a public URL (e.g., `your-app.railway.app`)
2. Visit the URL to test your application
3. Check logs in Railway dashboard if there are issues

## Post-Deployment

### Create Admin User

You'll need to create an admin user to access the application:

**Option 1: Via Railway Shell**
```bash
railway shell
node -e "
const bcrypt = require('bcrypt');
const db = require('./database');
(async () => {
  const hash = await bcrypt.hash('admin123', 10);
  await db.run(
    'INSERT INTO users (username, password, email, role) VALUES (\$1, \$2, \$3, \$4)',
    ['admin', hash, 'admin@example.com', 'admin']
  );
  console.log('Admin user created!');
  process.exit(0);
})();
"
```

**Option 2: Register via UI**
1. Go to your deployed app
2. Click "Register"
3. Create first user
4. Use Railway shell to promote to admin:
```bash
railway shell
node -e "
const db = require('./database');
(async () => {
  await db.run('UPDATE users SET role = \$1 WHERE username = \$2', ['admin', 'your-username']);
  console.log('User promoted to admin!');
  process.exit(0);
})();
"
```

### Monitor Your Application

**View Logs:**
1. Railway Dashboard → Your App → Deployments → View Logs
2. Or use CLI: `railway logs`

**Check Metrics:**
- Railway Dashboard → Your App → Metrics
- Monitor CPU, memory, and network usage

**Database Management:**
- Railway Dashboard → PostgreSQL Service
- View connection info, metrics, and backups

## Troubleshooting

### Database Connection Issues

**Error:** `ECONNREFUSED` or `Connection refused`
- Check that PostgreSQL service is running
- Verify `DATABASE_URL` is set correctly
- Ensure app and database are in the same project

**Error:** `relation "users" does not exist`
- Database schema not initialized
- Run `railway run node init-db.js`

### File Upload Issues

**Error:** `ENOENT: no such file or directory`
- Volume not mounted correctly
- Verify mount path is `/app/uploads`
- Check volume is attached to the correct service

**Files disappear after redeploy:**
- Volume not configured
- Files were stored in container (ephemeral)
- Add volume as described in Step 4

### Application Crashes

**Check logs:**
```bash
railway logs
```

**Common issues:**
- Missing environment variables (JWT_SECRET, SESSION_SECRET)
- Database connection errors
- Port binding issues (Railway sets PORT automatically)

### Slow Performance

- Upgrade Railway plan (free tier has limitations)
- Check database query performance
- Add database indexes (already included in init-db.js)
- Consider using a CDN for static assets

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NODE_ENV` | Yes | - | Set to `production` |
| `DATABASE_URL` | Yes | - | Auto-set by Railway PostgreSQL |
| `JWT_SECRET` | Yes | - | Secret for JWT tokens (64+ chars) |
| `SESSION_SECRET` | Yes | - | Secret for sessions (64+ chars) |
| `PORT` | No | 3000 | Auto-set by Railway |
| `RATE_LIMIT_WINDOW_MS` | No | 900000 | Rate limit window (15 min) |
| `RATE_LIMIT_MAX_REQUESTS` | No | 100 | Max requests per window |

## Updating Your Application

```bash
# Make changes locally
git add .
git commit -m "Your changes"
git push origin main
```

Railway will automatically:
1. Detect the push
2. Build new Docker image
3. Deploy with zero downtime
4. Keep your volume data intact

## Cost Estimation

**Railway Pricing (as of 2024):**
- **Free Tier**: $5 credit/month, ~500 hours
- **Pro Plan**: $20/month base + usage

**Typical Monthly Cost:**
- Small app: Free tier sufficient
- Medium traffic: $5-15/month
- High traffic: $20-50/month

**What uses resources:**
- PostgreSQL database: ~$5/month
- App container: Based on CPU/RAM usage
- Volume storage: ~$0.25/GB/month
- Bandwidth: Usually included

## Backup Strategy

### Database Backups

Railway automatically backs up PostgreSQL databases.

**Manual backup:**
```bash
railway run pg_dump > backup.sql
```

**Restore from backup:**
```bash
railway run psql < backup.sql
```

### File Backups

Volume data is persistent but should be backed up regularly:

```bash
# Using Railway CLI to download files
railway shell
tar -czf uploads-backup.tar.gz /app/uploads
# Then download via SFTP or similar
```

## Security Checklist

- [ ] Strong JWT_SECRET and SESSION_SECRET set
- [ ] No .env files in Git repository
- [ ] DATABASE_URL kept private
- [ ] Admin user created with strong password
- [ ] Rate limiting enabled (default 100 req/15min)
- [ ] HTTPS enabled (automatic with Railway)
- [ ] Regular database backups
- [ ] Monitor logs for suspicious activity

## Advanced Configuration

### Custom Domain

1. Railway Dashboard → Your App → Settings
2. Click "Generate Domain" or "Add Custom Domain"
3. Follow DNS configuration instructions

### Scaling

Railway auto-scales based on traffic. For manual scaling:
1. Settings → Resources
2. Adjust CPU and RAM allocations

### CI/CD Integration

Railway automatically deploys from GitHub. For more control:

```yaml
# .github/workflows/deploy.yml
name: Deploy to Railway
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy
        env:
          RAILWAY_TOKEN: ${{ secrets.RAILWAY_TOKEN }}
        run: |
          npm install -g @railway/cli
          railway up
```

## Support

- **Railway Docs**: [docs.railway.app](https://docs.railway.app)
- **Railway Discord**: [discord.gg/railway](https://discord.gg/railway)
- **Project Issues**: Check your GitHub repository issues

## Next Steps

After successful deployment:
1. Test all features (CRUD operations, file uploads, authentication)
2. Create regular users and test permissions
3. Set up monitoring/alerts
4. Plan backup schedule
5. Consider adding error tracking (Sentry, etc.)
6. Add health check endpoint for monitoring

---

**Ready to deploy?** Follow the steps above and your app will be live in minutes!
