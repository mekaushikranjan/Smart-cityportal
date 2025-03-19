const express = require("express");
const router = express.Router();
const complaintController = require("../controllers/complaintController");
const { isAuthenticated, isAdmin } = require("../middleware/authMiddleware");

// Consolidated GET route
router.get("/", isAuthenticated, (req, res) => {
  if (req.session.user.role === "admin") {
    complaintController.getAllComplaints(req, res);
  } else {
    complaintController.getUserComplaints(req, res);
  }
});

// User Routes
router.post("/", isAuthenticated, complaintController.createComplaint);
router.get("/user", isAuthenticated, complaintController.getUserComplaints);
router.delete("/:id", isAuthenticated, complaintController.deleteComplaint);

// Admin Routes
router.put("/:id/status", isAuthenticated, isAdmin, complaintController.updateComplaintStatus);

module.exports = router;