package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {

	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		panic("AUTH_SECRET env is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
}

func authMiddleware() gin.HandlerFunc {
	secret := os.Getenv("AUTH_SECRET") //validated at init()
	return func(ctx *gin.Context) {
		token := ctx.GetHeader("X-Auth-Token")
		if token != secret {
			ctx.IndentedJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}

func setupRouter() *gin.Engine {
	// gin.SetMode(gin.ReleaseMode) //Enable to run in prod mode. Hides all the logs.
	r := gin.Default()

	// Health route hence no auth needed
	r.GET("/health", health)

	// Authorized routes
	authorizedRouter := r.Group("/")
	authorizedRouter.Use(authMiddleware())
	authorizedRouter.GET("/admin", admin)
	return r
}

func main() {
	r := setupRouter()

	// 1. server setup
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 2. start server in go routine
	go func() {
		fmt.Println("Starting the https server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("server failed: %v", err))
		}
	}()

	// 3. wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("\n Shutting down server...")

	// 4. graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

}

// Routes
func health(ctx *gin.Context) {
	ctx.IndentedJSON(http.StatusOK, gin.H{"status": "OK"})
}
func admin(ctx *gin.Context) {
	ctx.IndentedJSON(http.StatusOK, gin.H{"status": "OK"})
}
