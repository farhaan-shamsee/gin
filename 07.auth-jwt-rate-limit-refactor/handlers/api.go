package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Profile(c *gin.Context) {
	userID := c.GetString("user_id")
	c.JSON(http.StatusOK, gin.H{
		"message": "Profile",
		"user_id": userID,
	})
}

func Admin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Admin access"})
}
