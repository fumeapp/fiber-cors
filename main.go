package main

import (
	fume "github.com/fumeapp/fiber"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(200).JSON(&fiber.Map{"message": "Fiber running with Fume"})
	})
	fume.Start(app, fume.Options{})
}
