const express = require("express");
const router = express.Router();
const User = require("./user");
const bcrypt = require("bcrypt");
const { isAuthenticated } = require("../middleware/authMiddleware");

router.put("/update", isAuthenticated, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // Use optional chaining to safely get the user id from the session.
    const userId = req.session?.user?.id;
    
    if (!userId) {
      return res.status(401).json({ message: "User not authenticated" });
    }

    // Build the update data only for the fields that are provided.
    const updatedData = {};
    if (name) updatedData.name = name;
    if (email) updatedData.email = email;
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updatedData.password = hashedPassword;
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updatedData, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "Profile updated successfully", user: updatedUser });
  } catch (error) {
    console.error("Update error:", error);
    res.status(500).json({ message: "Profile update failed", error: error.message });
  }
});

module.exports = router;
