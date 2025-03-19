// models/Complaint.js
const mongoose = require("mongoose");

const complaintSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    status: {
        type: String,
        enum: ["Pending", "In Progress", "Resolved"],
        default: "Pending",
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User", // Reference to the 'User' model
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

// Export the model to be used in routes
module.exports = mongoose.model("Complaint", complaintSchema);
