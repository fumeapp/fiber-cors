package cors

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Config defines the configuration options for the CORS middleware
type Config struct {
	// AllowOrigins is a comma-separated list of origins that are allowed to access the resource
	// Use * to allow all origins, but note that * cannot be used with AllowCredentials=true
	AllowOrigins string

	// AllowCredentials indicates whether the response to the request can be exposed when the credentials flag is true
	AllowCredentials bool

	// AllowHeaders is a comma-separated list of HTTP headers that are allowed to be used in CORS requests
	AllowHeaders string

	// ExposeHeaders is a comma-separated list of HTTP headers that can be exposed to the client
	ExposeHeaders string

	// AllowMethods is a comma-separated list of HTTP methods that are allowed for CORS requests
	AllowMethods string

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached
	// Default is 0, which means each preflight request performs a new OPTIONS request
	MaxAge int
}

// New creates a new CORS middleware handler
func New(config Config) fiber.Handler {
	allowedOriginsMap := make(map[string]bool)
	allowAll := false

	// Parse allowed origins
	if config.AllowOrigins != "" {
		origins := strings.Split(config.AllowOrigins, ",")
		for _, origin := range origins {
			origin = strings.TrimSpace(origin)
			if origin == "*" {
				allowAll = true
				break
			}
			// Add to allowed origins
			if origin != "" {
				allowedOriginsMap[origin] = true
			}
		}
	}

	// Validate configuration
	if config.AllowCredentials && allowAll {
		// According to spec section 3.2.5: If credentials mode is "include",
		// then Access-Control-Allow-Origin cannot be *
		panic("CORS: AllowCredentials=true is incompatible with AllowOrigins=*")
	}

	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")

		// Determine if this is a preflight request
		isPreflight := c.Method() == "OPTIONS" && c.Get("Access-Control-Request-Method") != ""
		isOptions := c.Method() == "OPTIONS"

		// Check if the request's origin is allowed according to the configuration
		originAllowed := false
		if origin != "" {
			if allowAll || len(allowedOriginsMap) == 0 || allowedOriginsMap[origin] {
				originAllowed = true
				// CORS spec: Echo actual origin instead of "*" wildcard
				c.Set("Access-Control-Allow-Origin", origin)
			}
		}

		// CORS spec: Only set headers for allowed origins
		if originAllowed || origin == "" {
			// Set Access-Control-Allow-Credentials if enabled
			if config.AllowCredentials {
				c.Set("Access-Control-Allow-Credentials", "true")
			}

			// Set CORS headers
			if config.AllowHeaders != "" {
				c.Set("Access-Control-Allow-Headers", config.AllowHeaders)
			}

			if config.AllowMethods != "" {
				c.Set("Access-Control-Allow-Methods", config.AllowMethods)
			}

			if config.ExposeHeaders != "" {
				c.Set("Access-Control-Expose-Headers", config.ExposeHeaders)
			}
		}

		if isPreflight {
			// Handle preflight request
			if originAllowed || origin == "" {
				// Handle request headers
				requestHeaders := c.Get("Access-Control-Request-Headers")
				if config.AllowHeaders == "" && requestHeaders != "" {
					// CORS spec: Echo requested headers when no specific headers configured
					c.Set("Access-Control-Allow-Headers", requestHeaders)
				}

				// Set Access-Control-Max-Age if configured
				if config.MaxAge > 0 {
					c.Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
				}
			}

			// Return 204 No Content for preflight
			return c.SendStatus(204)
		} else if isOptions {
			// Handle simple OPTIONS request (not a preflight)
			return c.SendStatus(204)
		}

		// CORS spec: For disallowed origins, process request but browser will block response
		return c.Next()
	}
}
