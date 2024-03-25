package main

import (
	"github.com/Smartdevs17/go_auth/controllers"
	"github.com/Smartdevs17/go_auth/initializers"
	"github.com/Smartdevs17/go_auth/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVars()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.POST("/auth/register", controllers.Register)
	r.POST("/auth/login", controllers.Login)
	r.GET("/auth/validate", middleware.RequireAuth, controllers.Validate)

	r.Run() // listen and serve on localhost:3000
}
