package main

import (
	"fmt"
	fume "github.com/fumeapp/fiber"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"runtime/debug"
	"time"
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
	config :=
		cors.Config{
			AllowOrigins:     "https://fiber-cors-nuxt.acidjazz.workers.dev, https://console.domain.com, http://localhost:3000",
			AllowCredentials: true,
			AllowHeaders:     "Origin, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, User-Agent",
			ExposeHeaders:    "Origin, User-Agent",
			AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD",
		}

	// configure CORS middleware
	app.Use(cors.New(config))

	app.Use(func(c *fiber.Ctx) error {
		fmt.Printf("→ %s %s | Origin: %s\n", c.Method(), c.Path(), c.Get("Origin"))
		fmt.Printf("→ Request Headers: %v\n", c.GetReqHeaders())
		err := c.Next()
		fmt.Printf("← Response Headers: %v\n", c.GetRespHeaders())
		return err
	})

	app.Get("/", func(c *fiber.Ctx) error {
		// Only expose serializable config fields
		configResponse := fiber.Map{
			"AllowOrigins":     config.AllowOrigins,
			"AllowCredentials": config.AllowCredentials,
			"AllowHeaders":     config.AllowHeaders,
			"ExposeHeaders":    config.ExposeHeaders,
			"AllowMethods":     config.AllowMethods,
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
