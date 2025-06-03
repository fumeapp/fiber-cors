package main

import (
	fume "github.com/fumeapp/fiber"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"runtime/debug"
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

	// configure CORS middleware
	app.Use(
		cors.New(
			cors.Config{
				AllowOrigins:     "https://console.ngrok.dev, https://api.ngrok.dev",
				AllowCredentials: true,
				AllowHeaders:     "Origin, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, User-Agent",
				ExposeHeaders:    "Origin, User-Agent",
				AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD",
			},
		),
	)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(200).JSON(&fiber.Map{"message": "Fiber running with Fume", "version": getFiberVersion()})
	})
	fume.Start(app, fume.Options{})
}
