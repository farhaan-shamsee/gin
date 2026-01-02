package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/farhaan-shamsee/07.auth-jwt-rate-limit-refactor/handlers"
	"github.com/farhaan-shamsee/07.auth-jwt-rate-limit-refactor/middleware"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func setupRouter(cfg Config) *gin.Engine {
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Global rate limiting: 100 requests per second with burst of 10
	limiter := middleware.NewIPRateLimiter(rate.Limit(100), 10)
	r.Use(middleware.RateLimit(limiter))

	// PUBLIC routes
	r.POST("/login", handlers.Login(cfg.JWTSecret, cfg.RefreshSecret))
	r.POST("/refresh", handlers.Refresh(cfg.JWTSecret, cfg.RefreshSecret))

	// PROTECTED: JWT + Rate Limited
	api := r.Group("/api")
	api.Use(middleware.JWTAuth(cfg.JWTSecret))
	api.GET("/profile", handlers.Profile)
	api.GET("/admin", handlers.Admin)

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
		fmt.Printf("🔐 JWT + Rate Limit Server :%s\n", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("\n🛑 Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
