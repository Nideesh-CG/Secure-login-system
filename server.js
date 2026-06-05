require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const useragent = require('express-useragent');
const path = require('path');

const { getDatabase } = require('./database');
const { generalLimiter } = require('./middleware/rateLimiter');
const authRouter = require('./routes/auth');
const userRouter = require('./routes/user');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Apply Helmet to set secure HTTP headers (CSP, HSTS, X-Content-Type-Options, etc.)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // Allow Google fonts and local self style imports
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        // Allow local image assets and data: URIs (crucial for QR codes)
        imgSrc: ["'self'", "data:"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: null // disable force https upgrade for local development
      }
    }
  })
);

// 2. Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.SESSION_SECRET));
app.use(useragent.express());

// 3. API Rate Limiting (Protects from API DDoS/scraping)
app.use('/api/', generalLimiter);

// 4. API Endpoints
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

// 5. Serve static files from 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// 6. SPA Catch-all (Redirect unhandled page requests to index.html)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 7. Initialize SQLite DB and start Listening
async function startServer() {
  try {
    console.log('Initializing secure database...');
    await getDatabase();
    console.log('Database initialized successfully.');
    
    app.listen(PORT, () => {
      console.log(`===================================================`);
      console.log(`🔒 Secure Login System server running!`);
      console.log(`🌐 URL: http://localhost:${PORT}`);
      console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`===================================================`);
    });
  } catch (err) {
    console.error('CRITICAL ERROR: Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
