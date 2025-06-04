package main

import (
	"runtime/debug"
	"time"

	fume "github.com/fumeapp/fiber"
	"github.com/gofiber/fiber/v2"

	"github.com/fumeapp/fiber-cors/pkg/cors"
)

func getFiberVersion() string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range buildInfo.Deps {
		if dep.Path == "github.com/gofiber/fiber/v2" {
			return dep.Version
		}
	}
	return "unknown"
}

func main() {
	app := fiber.New()

	// Get default CORS configuration
	corsConfig := cors.DefaultConfig()

	app.Use(cors.New(corsConfig))

	app.Get("/", func(c *fiber.Ctx) error {
		// Only expose serializable config fields
		configResponse := fiber.Map{
			"AllowOrigins":     corsConfig.AllowOrigins,
			"AllowCredentials": corsConfig.AllowCredentials,
			"AllowHeaders":     corsConfig.AllowHeaders,
			"ExposeHeaders":    corsConfig.ExposeHeaders,
			"AllowMethods":     corsConfig.AllowMethods,
		}
		return c.Status(200).JSON(&fiber.Map{
			"message":   "Fiber running with Fume",
			"version":   getFiberVersion(),
			"config":    configResponse,
			"timestamp": time.Now().Unix(),
		})
	})
	fume.Start(app, fume.Options{})
}
