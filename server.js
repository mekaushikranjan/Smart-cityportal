const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const MongoStore = require("connect-mongo");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
require("dotenv").config();
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const { body } = require('express-validator');
const User = require("./models/User");
const { generateOTP, hashOTP, verifyOTP, sendOTP } = require("./utils/otpService");

const app = express();

// Validate essential environment variables
const requiredEnvVars = ["SESSION_SECRET", "MONGO_URI", "FRONTEND_URL"];
requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    console.error(`⚠️ Missing environment variable: ${varName}`);
    process.exit(1);
  }
});

// Database Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: "majority",
})
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Use Helmet for security headers
app.use(helmet());

// CORS Configuration
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Trust reverse proxy
app.set("trust proxy", 1);

// Session Configuration with environment-dependent cookie settings
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI,
  collectionName: "sessions",
  crypto: {
    secret: process.env.SESSION_STORE_SECRET || process.env.SESSION_SECRET
  },
  touchAfter: 24 * 3600 // Reduce database writes (update session once per day)
});

app.use(session({
  name: "smartcity.sid",
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Secure only in production
    sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax", // Adjust sameSite
    maxAge: 24 * 60 * 60 * 1000,
    domain: process.env.COOKIE_DOMAIN || undefined
  }
}));

// Parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// General Rate Limiting for authentication routes
app.use("/api/auth", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests, please try again later" }
}));

// OTP Rate Limiting (Stronger limits for OTP requests)
const otpRateLimit = rateLimit({
  windowMs: parseInt(process.env.OTP_EXPIRY_MINUTES || 10) * 60 * 1000,
  max: parseInt(process.env.OTP_LIMIT || 5),
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many OTP requests, please wait before trying again" }
});
app.use("/api/auth/resend-otp", otpRateLimit);
app.use("/api/auth/verify-otp", otpRateLimit);

// Validation rules for user registration
const registerValidation = [
  body('name')
    .notEmpty().withMessage('Name is required')
    .trim()
    .isLength({ max: 100 }).withMessage('Name must be less than 100 characters'),
  
  body('email')
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail()
    .trim(),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
    .isLength({ max: 100 }).withMessage('Password must be less than 100 characters'),
];

// Validation rules for user login
const loginValidation = [
  body('email')
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail()
    .trim(),
  
  body('password')
    .notEmpty().withMessage('Password is required'),
];

// Register a new user
const register = async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validate required fields
    if (!email || !password || !name) {
      return res.status(400).json({
        success: false,
        code: "INVALID_REQUEST",
        message: "Please provide all required fields"
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        code: "USER_EXISTS",
        message: "Account with this email already exists"
      });
    }

    // Generate OTP and hash it
    const otp = generateOTP();
    const hashedOTP = await hashOTP(otp);

    // Store user data and OTP in session
    req.session.tempUser = {
      email: email.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      name: name.trim(),
      otp: hashedOTP,
      otpExpires: new Date(Date.now() + 10 * 1000) // OTP expires in 10 seconds
    };

    // Send OTP via email
    const emailSent = await sendOTP(email, otp);
    if (!emailSent) {
      return res.status(500).json({
        success: false,
        code: "EMAIL_ERROR",
        message: "Failed to send verification email"
      });
    }

    res.status(201).json({
      success: true,
      message: "Registration initiated. Please verify your email."
    });

  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({
      success: false,
      code: "SERVER_ERROR",
      message: "Internal server error"
    });
  }
};

// Verify user's OTP
const verifyUserOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Validate required fields
    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        code: "INVALID_REQUEST",
        message: "Email and verification code are required"
      });
    }

    // Check if temp user data exists in session
    const tempUser = req.session.tempUser;
    if (!tempUser || tempUser.email !== email.toLowerCase()) {
      return res.status(400).json({
        success: false,
        code: "INVALID_OTP",
        message: "Invalid verification code"
      });
    }

    // Verify OTP and expiration
    if (!(await verifyOTP(otp, tempUser.otp)) || new Date() > tempUser.otpExpires) {
      return res.status(400).json({
        success: false,
        code: "INVALID_OTP",
        message: "Invalid or expired verification code"
      });
    }

    // Create new user
    const user = new User({
      email: tempUser.email,
      password: tempUser.password,
      name: tempUser.name,
      role: "user", // Default role set to 'user'
      emailVerified: true
    });

    await user.save();

    // Clear temp user data from session
    req.session.tempUser = null;

    res.json({
      success: true,
      message: "Email verified and registration completed successfully",
      user: { email: user.email, name: user.name }
    });
  } catch (error) {
    console.error("OTP Verification Error:", error);
    res.status(500).json({
      success: false,
      code: "SERVER_ERROR",
      message: "Internal server error"
    });
  }
};

// Login an existing user
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        code: "INVALID_REQUEST",
        message: "Please provide both email and password"
      });
    }

    // Find user and include password field
    const user = await User.findOne({ email: email.toLowerCase() }).select("+password");

    // Validate credentials
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        code: "INVALID_CREDENTIALS",
        message: "Invalid email or password"
      });
    }

    // Regenerate session for security
    req.session.regenerate((err) => {
      if (err) {
        console.error("Session Regeneration Error:", err);
        return res.status(500).json({
          success: false,
          code: "SESSION_ERROR",
          message: "Authentication system error"
        });
      }

      // User data to store in session
      const sessionUser = {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      };

      req.session.user = sessionUser;

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session Save Error:", saveErr);
          return res.status(500).json({
            success: false,
            code: "SESSION_ERROR",
            message: "Authentication system error"
          });
        }
        res.json({
          success: true,
          message: "Login successful",
          user: sessionUser,
          token: req.sessionID // Return session ID as token
        });
      });
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({
      success: false,
      code: "SERVER_ERROR",
      message: "Internal server error"
    });
  }
};

// Check session endpoint
app.get('/api/auth/checkSession', (req, res) => {
  if (req.session.user) {
    res.json({ isAuthenticated: true, user: req.session.user });
  } else {
    res.json({ isAuthenticated: false });
  }
});

// Add login and register routes
app.post('/api/auth/register', register);
app.post('/api/auth/login', login);
app.post('/api/auth/verify-otp', verifyUserOTP);

// Start Server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`   Frontend URL: ${process.env.FRONTEND_URL}`);
});