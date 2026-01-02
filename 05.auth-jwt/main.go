package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	JWTSecret     string
	RefreshSecret string
	Port          string
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

func loadConfig() Config {
	cfg := Config{}
	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTSecret == "" {
		panic("❌ JWT_SECRET required")
	}
	cfg.RefreshSecret = os.Getenv("REFRESH_SECRET")
	if cfg.RefreshSecret == "" {
		panic("❌ REFRESH_SECRET required")
	}
	cfg.Port = os.Getenv("PORT")
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	return cfg
}

func generateTokens(cfg Config, username string) Tokens {
	// Access Token: 15 minutes
	accessClaims := jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessStr, _ := accessToken.SignedString([]byte(cfg.JWTSecret))

	// Refresh Token: 7 days + rotation flag
	refreshClaims := jwt.MapClaims{
		"sub":      username,
		"exp":      time.Now().Add(7 * 24 * time.Hour).Unix(),
		"rotating": true, // Forces rotation on use
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshStr, _ := refreshToken.SignedString([]byte(cfg.RefreshSecret))

	return Tokens{
		AccessToken:  accessStr,
		RefreshToken: refreshStr,
		ExpiresIn:    15 * 60, // 15 minutes in seconds
	}
}

func validateToken(tokenStr string, secret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	return claims, nil
}

func jwtAuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Expect: "Bearer <token>"
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			c.Abort()
			return
		}

		tokenStr := authHeader[7:]
		claims, err := validateToken(tokenStr, []byte(secret))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Add user info to context
		c.Set("user_id", claims["sub"])
		c.Next()
	}
}

func setupRouter(cfg Config) *gin.Engine {
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.IndentedJSON(http.StatusOK, gin.H{"status": "OK"})
	})
	// Public routes
	r.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// Mock user validation (replace with DB)
		if req.Username != "admin" || req.Password != "password" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		tokens := generateTokens(cfg, req.Username)
		c.JSON(http.StatusOK, tokens)
	})

	r.POST("/refresh", func(c *gin.Context) {
		refreshToken := c.PostForm("refresh_token")
		if refreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token required"})
			return
		}

		claims, err := validateToken(refreshToken, []byte(cfg.RefreshSecret))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		// Rotate: generate new tokens
		tokens := generateTokens(cfg, claims["sub"].(string))
		c.JSON(http.StatusOK, tokens)
	})

	// Protected routes
	api := r.Group("/api")
	api.Use(jwtAuthMiddleware(cfg.JWTSecret))

	api.GET("/profile", func(c *gin.Context) {
		userID := c.GetString("user_id")
		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome to profile",
			"user_id": userID,
		})
	})

	api.GET("/admin", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Admin access granted"})
	})

	return r
}

func main() {
	cfg := loadConfig()
	r := setupRouter(cfg)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		fmt.Printf("🚀 JWT Server on :%s\n", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("❌ Server failed: %v", err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("\n🛑 Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("❌ Shutdown error:", err)
	}
	fmt.Println("👋 Server stopped")
}
