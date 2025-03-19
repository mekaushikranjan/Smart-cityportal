router.put("/make-admin/:id", async (req, res) => {
    if (!req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({ message: "Unauthorized" });
    }
  
    try {
      const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        { role: "admin" },
        { new: true } // returns the updated document
      );
      
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json({ message: "User is now an admin", user: updatedUser });
    } catch (error) {
      console.error("Error updating user role:", error);
      res.status(500).json({ message: "Error updating user role" });
    }
  });
