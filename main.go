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

	corsConfig := cors.Config{
		AllowOrigins:     "https://fiber-cors-nuxt.acidjazz.workers.dev, https://console.domain.com, http://localhost:3000",
		AllowCredentials: true,
		AllowHeaders:     "Origin, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, User-Agent",
		ExposeHeaders:    "Origin, User-Agent",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD",
		MaxAge:           86400, // Cache preflight results for 24 hours (in seconds)
	}

	app.Use(cors.New(corsConfig))

	app.Get("/", func(c *fiber.Ctx) error {
		configResponse := fiber.Map{
			"AllowOrigins":     corsConfig.AllowOrigins,
			"AllowCredentials": corsConfig.AllowCredentials,
			"AllowHeaders":     corsConfig.AllowHeaders,
			"ExposeHeaders":    corsConfig.ExposeHeaders,
			"AllowMethods":     corsConfig.AllowMethods,
			"MaxAge":           corsConfig.MaxAge,
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
