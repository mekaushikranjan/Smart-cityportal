const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const crypto = require('crypto');

// Create email transporter with robust error handling
let transporter;

/**
 * Initialize email transporter
 * @returns {boolean} True if transporter initialized successfully
 */
const initTransporter = () => {
    try {
        transporter = nodemailer.createTransport({
            host: "smtp.gmail.com",
            port: 465,
            secure: true, // Use SSL
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD // Use App Password, not regular password
            },
            debug: true, // Enable debug output
            logger: true // Log information about the email sending process
        });
        
        // Verify connection configuration
        transporter.verify(function(error, success) {
            if (error) {
                console.error("Transporter verification failed:", error);
                return false;
            } else {
                console.log("Server is ready to send emails");
                return true;
            }
        });
        
        return true;
    } catch (error) {
        console.error("Failed to create email transporter:", error);
        return false;
    }
};

// Initialize transporter on module load
initTransporter();

/**
 * Generate a secure 6-digit OTP
 * @returns {string} 6-digit OTP
 */
const generateOTP = () => {
    try {
        const min = 100000;
        const max = 999999;
        return crypto.randomInt(min, max + 1).toString();
    } catch (error) {
        console.error("Error generating OTP with crypto.randomInt:", error);
        // Fallback to Math.random if crypto fails
        return Math.floor(100000 + Math.random() * 900000).toString();
    }
};

/**
 * Hash OTP before storing
 * @param {string} otp - The OTP to hash
 * @returns {Promise<string>} Hashed OTP
 */
const hashOTP = async (otp) => {
    if (!otp) throw new Error("OTP is required");
    return await bcrypt.hash(otp.toString(), 8);
};

/**
 * Compare provided OTP with stored hash
 * @param {string} inputOTP - The OTP to verify
 * @param {string} storedHash - The stored hash to compare against
 * @returns {Promise<boolean>} True if OTP matches
 */
const verifyOTP = async (inputOTP, storedHash) => {
    if (!inputOTP || !storedHash) return false;
    return await bcrypt.compare(inputOTP.toString(), storedHash);
};

/**
 * Send OTP via email
 * @param {string} email - Recipient email address
 * @param {string} otp - The OTP to send
 * @returns {Promise<boolean>}
 */
const sendOTP = async (email, otp) => {
    if (!transporter) {
        console.log("Email transporter not initialized, attempting to initialize...");
        if (!initTransporter()) {
            console.error("Failed to initialize email transporter");
            return false;
        }
    }

    if (!email || !otp) {
        console.error("Email and OTP are required");
        return false;
    }

    const mailOptions = {
        from: process.env.EMAIL_FROM || `"Smart City Authentication" <${process.env.EMAIL_USERNAME}>`,
        to: email,
        subject: "Your Smart City Portal Verification Code",
        html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
        <h1 style="color: #333; text-align: center;">Email Verification</h1>
        <p>Use the following code to verify your email address for Smart City Portal:</p>
        <div style="text-align: center; margin: 20px 0;">
          <h2 style="letter-spacing: 5px; font-size: 32px; background-color: #f5f5f5; padding: 10px; border-radius: 5px;">${otp}</h2>
        </div>
        <p>This code expires in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.</p>
        <p>If you didn't request this code, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #666; font-size: 12px; text-align: center;">This is an automated message, please do not reply.</p>
      </div>
    `,
        // Add a text version for email clients that don't support HTML
        text: `Your Smart City Portal verification code is: ${otp}\nThis code expires in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.`
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent details:', {
            messageId: info.messageId,
            response: info.response,
            accepted: info.accepted,
            rejected: info.rejected,
            envelope: info.envelope
        });
        return true;
    } catch (error) {
        console.error("Error sending OTP email:", error);
        return false;
    }
};

module.exports = { generateOTP, hashOTP, verifyOTP, sendOTP };