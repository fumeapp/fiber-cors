package cors

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

type Config struct {
	AllowOrigins     string
	AllowCredentials bool
	AllowHeaders     string
	ExposeHeaders    string
	AllowMethods     string
}

func DefaultConfig() Config {
	return Config{
		AllowOrigins:     "https://fiber-cors-nuxt.acidjazz.workers.dev, https://console.domain.com, http://localhost:3000",
		AllowCredentials: true,
		AllowHeaders:     "Origin, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, User-Agent",
		ExposeHeaders:    "Origin, User-Agent",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD",
	}
}

// New returns a middleware that sets CORS headers manually
func New(config Config) fiber.Handler {
	// Convert comma-separated origins to a slice for easier checking
	allowedOriginsMap := make(map[string]bool)
	if config.AllowOrigins != "" {
		// Parse comma-separated values
		origins := strings.Split(config.AllowOrigins, ",")
		for _, origin := range origins {
			// Trim spaces
			origin = strings.TrimSpace(origin)
			if origin != "" {
				allowedOriginsMap[origin] = true
			}
		}
	}

	// Return the middleware handler
	return func(c *fiber.Ctx) error {
		// Get the origin from the request
		origin := c.Get("Origin")

		// Check if the origin is allowed
		if origin != "" {
			if len(allowedOriginsMap) == 0 || allowedOriginsMap[origin] {
				c.Set("Access-Control-Allow-Origin", origin)
			}
		}

		// Set other CORS headers
		if config.AllowCredentials {
			c.Set("Access-Control-Allow-Credentials", "true")
		}

		if config.AllowHeaders != "" {
			c.Set("Access-Control-Allow-Headers", config.AllowHeaders)
		}

		if config.ExposeHeaders != "" {
			c.Set("Access-Control-Expose-Headers", config.ExposeHeaders)
		}

		if config.AllowMethods != "" {
			c.Set("Access-Control-Allow-Methods", config.AllowMethods)
		}

		// Handle preflight OPTIONS request
		if c.Method() == "OPTIONS" {
			return c.SendStatus(204) // No content needed for OPTIONS
		}

		// Proceed with the request
		return c.Next()
	}
}
