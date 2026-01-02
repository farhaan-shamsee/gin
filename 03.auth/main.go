package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func authMiddleware() gin.HandlerFunc {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		panic("AUTH_SECRET env is required")
	}
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
	// gin.SetMode(gin.ReleaseMode) //NEable to run in prod mode. Hides all the logs.
	r := gin.Default()
	r.Use(gin.Logger())

	return r
}

func main() {
	r := setupRouter()
	// Health route hence no auth needed
	r.GET("/health", health)

	// Authorized routes
	authorizedRouter := r.Group("/")
	authorizedRouter.Use(authMiddleware())
	authorizedRouter.GET("/admin", admin)

	fmt.Println("Starting the gin server")
	_ = r.Run(":8080")
}

// Routes
func health(ctx *gin.Context) {
	ctx.IndentedJSON(http.StatusOK, gin.H{"status": "OK"})
}
func admin(ctx *gin.Context) {
	ctx.IndentedJSON(http.StatusOK, gin.H{"status": "OK"})
}
