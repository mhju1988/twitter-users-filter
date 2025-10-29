# Use Node.js LTS version
FROM node:18-alpine

# Install build dependencies for native modules (bcrypt, better-sqlite3 if needed)
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Create directory for uploads (will be mounted to Railway Volume)
RUN mkdir -p /app/uploads/videos

# Set environment to production
ENV NODE_ENV=production

# Expose port (Railway will inject PORT env var)
EXPOSE 3000

# Start the application (using async/PostgreSQL version)
CMD ["node", "server-async.js"]
