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

func New(config Config) fiber.Handler {
	allowedOriginsMap := make(map[string]bool)
	allowAll := false

	if config.AllowOrigins != "" {
		origins := strings.Split(config.AllowOrigins, ",")
		for _, origin := range origins {
			origin = strings.TrimSpace(origin)
			if origin == "*" {
				allowAll = true
				break
			}
			if origin != "" {
				allowedOriginsMap[origin] = true
			}
		}
	}

	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")

		if origin != "" {
			if allowAll || len(allowedOriginsMap) == 0 || allowedOriginsMap[origin] {
				c.Set("Access-Control-Allow-Origin", origin)
			}
		}

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

		if c.Method() == "OPTIONS" {
			return c.SendStatus(204)
		}

		return c.Next()
	}
}
