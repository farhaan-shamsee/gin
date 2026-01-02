package handlers

import (
	"net/http"

	"github.com/farhaan-shamsee/07.auth-jwt-rate-limit-refactor/utils"
	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func Login(jwtSecret, refreshSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// Mock auth (replace with DB)
		if req.Username != "admin" || req.Password != "password" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		tokens := utils.GenerateTokens(jwtSecret, refreshSecret, req.Username)
		c.JSON(http.StatusOK, tokens)
	}
}

func Refresh(jwtSecret, refreshSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		refreshToken := c.PostForm("refresh_token")
		if refreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token required"})
			return
		}

		claims, err := utils.ValidateToken(refreshToken, []byte(refreshSecret))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		// Rotate tokens
		tokens := utils.GenerateTokens(jwtSecret, refreshSecret, claims["sub"].(string))
		c.JSON(http.StatusOK, tokens)
	}
}
