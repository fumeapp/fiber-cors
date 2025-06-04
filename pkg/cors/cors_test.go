package cors

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestCorsMiddleware(t *testing.T) {
	tests := []struct {
		name                 string
		config               Config
		requestOrigin        string
		requestMethod        string
		requestHeaders       map[string]string
		expectedOrigin       string
		expectedStatus       int
		expectedMaxAge       string
		expectPreflightCheck bool
	}{
		{
			name: "allowed origin",
			config: Config{
				AllowOrigins:     "https://example.com, https://allowed.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST",
			},
			requestOrigin:  "https://allowed.com",
			requestMethod:  "GET",
			expectedOrigin: "https://allowed.com",
			expectedStatus: 200,
		},
		{
			name: "disallowed origin",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST",
			},
			requestOrigin:  "https://disallowed.com",
			requestMethod:  "GET",
			expectedOrigin: "", // No Access-Control-Allow-Origin header for disallowed origins
			expectedStatus: 200,
		},
		{
			name: "empty origin",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST",
			},
			requestOrigin:  "",
			requestMethod:  "GET",
			expectedOrigin: "",
			expectedStatus: 200,
		},
		{
			name: "options request",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST, OPTIONS",
			},
			requestOrigin:  "https://example.com",
			requestMethod:  "OPTIONS",
			expectedOrigin: "https://example.com",
			expectedStatus: 204,
		},
		{
			name: "empty config - all origins allowed",
			config: Config{
				AllowOrigins:     "", // Empty AllowOrigins means all origins are allowed
				AllowCredentials: false,
				AllowHeaders:     "",
				ExposeHeaders:    "",
				AllowMethods:     "",
			},
			requestOrigin:  "https://example.com",
			requestMethod:  "GET",
			expectedOrigin: "https://example.com", // Origin is allowed with empty config
			expectedStatus: 200,
		},
		{
			name: "preflight request with Access-Control-Request-Method",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST, OPTIONS",
				MaxAge:           3600,
			},
			requestOrigin: "https://example.com",
			requestMethod: "OPTIONS",
			requestHeaders: map[string]string{
				"Access-Control-Request-Method": "POST",
			},
			expectedOrigin:       "https://example.com",
			expectedStatus:       204,
			expectedMaxAge:       "3600",
			expectPreflightCheck: true,
		},
		{
			name: "preflight request with custom headers",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type, Authorization",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST, OPTIONS",
				MaxAge:           3600,
			},
			requestOrigin: "https://example.com",
			requestMethod: "OPTIONS",
			requestHeaders: map[string]string{
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "Authorization",
			},
			expectedOrigin:       "https://example.com",
			expectedStatus:       204,
			expectedMaxAge:       "3600",
			expectPreflightCheck: true,
		},
		{
			name: "preflight request with echo back headers",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST, OPTIONS",
				MaxAge:           3600,
			},
			requestOrigin: "https://example.com",
			requestMethod: "OPTIONS",
			requestHeaders: map[string]string{
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "Authorization, X-Custom-Header",
			},
			expectedOrigin:       "https://example.com",
			expectedStatus:       204,
			expectedMaxAge:       "3600",
			expectPreflightCheck: true,
		},
		{
			name: "preflight request with disallowed origin",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST, OPTIONS",
				MaxAge:           3600,
			},
			requestOrigin: "https://disallowed.com",
			requestMethod: "OPTIONS",
			requestHeaders: map[string]string{
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "Authorization",
			},
			expectedOrigin:       "", // No Access-Control-Allow-Origin header for disallowed origins
			expectedStatus:       204,
			expectedMaxAge:       "", // No Max-Age header for disallowed origins
			expectPreflightCheck: true,
		},
		{
			name: "case-insensitive origin matching",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST, OPTIONS",
			},
			requestOrigin:  "https://EXAMPLE.com",
			requestMethod:  "GET",
			expectedOrigin: "https://EXAMPLE.com", // Should match despite case difference
			expectedStatus: 200,
		},
		{
			name: "header validation for preflight",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "", // Empty AllowHeaders to test validation
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "GET, POST, OPTIONS",
			},
			requestOrigin: "https://example.com",
			requestMethod: "OPTIONS",
			requestHeaders: map[string]string{
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "content-type, authorization, x-csrf-token, host", // Mix of safe and unsafe headers
			},
			expectedOrigin:       "https://example.com",
			expectedStatus:       204,
			expectPreflightCheck: true,
		},
		{
			name: "default methods when not configured",
			config: Config{
				AllowOrigins:     "https://example.com",
				AllowCredentials: true,
				AllowHeaders:     "Content-Type",
				ExposeHeaders:    "X-Custom",
				AllowMethods:     "", // Empty AllowMethods to test defaults
			},
			requestOrigin:  "https://example.com",
			requestMethod:  "GET",
			expectedOrigin: "https://example.com",
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(New(tt.config))
			app.Get("/", func(c *fiber.Ctx) error {
				return c.SendStatus(200)
			})

			req := httptest.NewRequest(tt.requestMethod, "/", nil)
			if tt.requestOrigin != "" {
				req.Header.Set("Origin", tt.requestOrigin)
			}

			// Set additional request headers if provided
			if tt.requestHeaders != nil {
				for key, value := range tt.requestHeaders {
					req.Header.Set(key, value)
				}
			}

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Failed to test request: %v", err)
			}

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d but got %d", tt.expectedStatus, resp.StatusCode)
			}

			origin := resp.Header.Get("Access-Control-Allow-Origin")
			if origin != tt.expectedOrigin {
				t.Errorf("Expected Access-Control-Allow-Origin to be %q but got %q", tt.expectedOrigin, origin)
			}

			// Only check for CORS headers if the origin is allowed or empty
			originAllowed := tt.expectedOrigin != "" || tt.requestOrigin == ""

			if originAllowed {
				if tt.config.AllowCredentials {
					credentials := resp.Header.Get("Access-Control-Allow-Credentials")
					if credentials != "true" {
						t.Errorf("Expected Access-Control-Allow-Credentials to be 'true' but got %q", credentials)
					}
				}

				if tt.config.AllowHeaders != "" {
					headers := resp.Header.Get("Access-Control-Allow-Headers")
					if headers != tt.config.AllowHeaders {
						t.Errorf("Expected Access-Control-Allow-Headers to be %q but got %q", tt.config.AllowHeaders, headers)
					}
				}

				if tt.config.ExposeHeaders != "" {
					exposeHeaders := resp.Header.Get("Access-Control-Expose-Headers")
					if exposeHeaders != tt.config.ExposeHeaders {
						t.Errorf("Expected Access-Control-Expose-Headers to be %q but got %q", tt.config.ExposeHeaders, exposeHeaders)
					}
				}

				if tt.config.AllowMethods != "" {
					methods := resp.Header.Get("Access-Control-Allow-Methods")
					if methods != tt.config.AllowMethods {
						t.Errorf("Expected Access-Control-Allow-Methods to be %q but got %q", tt.config.AllowMethods, methods)
					}
				}
			} else {
				// For disallowed origins, verify that no CORS headers are present
				credentials := resp.Header.Get("Access-Control-Allow-Credentials")
				if credentials != "" {
					t.Errorf("Expected no Access-Control-Allow-Credentials header for disallowed origin, but got %q", credentials)
				}

				headers := resp.Header.Get("Access-Control-Allow-Headers")
				if headers != "" {
					t.Errorf("Expected no Access-Control-Allow-Headers header for disallowed origin, but got %q", headers)
				}

				exposeHeaders := resp.Header.Get("Access-Control-Expose-Headers")
				if exposeHeaders != "" {
					t.Errorf("Expected no Access-Control-Expose-Headers header for disallowed origin, but got %q", exposeHeaders)
				}

				methods := resp.Header.Get("Access-Control-Allow-Methods")
				if methods != "" {
					t.Errorf("Expected no Access-Control-Allow-Methods header for disallowed origin, but got %q", methods)
				}
			}

			// Check Max-Age header for preflight requests (only for allowed origins)
			if tt.expectPreflightCheck && tt.expectedMaxAge != "" {
				if originAllowed {
					maxAge := resp.Header.Get("Access-Control-Max-Age")
					if maxAge != tt.expectedMaxAge {
						t.Errorf("Expected Access-Control-Max-Age to be %q but got %q", tt.expectedMaxAge, maxAge)
					}
				} else {
					maxAge := resp.Header.Get("Access-Control-Max-Age")
					if maxAge != "" {
						t.Errorf("Expected no Access-Control-Max-Age header for disallowed origin, but got %q", maxAge)
					}
				}
			}

			// Test default methods when not configured
			if tt.name == "default methods when not configured" {
				methods := resp.Header.Get("Access-Control-Allow-Methods")
				expectedDefaultMethods := "GET, POST, HEAD, OPTIONS"
				if methods != expectedDefaultMethods {
					t.Errorf("Expected default Access-Control-Allow-Methods to be %q but got %q", expectedDefaultMethods, methods)
				}
			}

			// Test header validation for preflight
			if tt.name == "header validation for preflight" && tt.expectPreflightCheck {
				headers := resp.Header.Get("Access-Control-Allow-Headers")
				if headers != "" {
					// Check that unsafe headers like "host" are not included
					headersList := strings.Split(headers, ",")
					for _, header := range headersList {
						header = strings.TrimSpace(strings.ToLower(header))
						if header == "host" {
							t.Errorf("Unsafe header 'host' should not be included in Access-Control-Allow-Headers")
						}
					}

					// Check that safe headers are included
					foundContentType := false
					foundAuthorization := false
					foundCsrfToken := false

					for _, header := range headersList {
						header = strings.TrimSpace(strings.ToLower(header))
						if header == "content-type" {
							foundContentType = true
						} else if header == "authorization" {
							foundAuthorization = true
						} else if header == "x-csrf-token" {
							foundCsrfToken = true
						}
					}

					if !foundContentType {
						t.Errorf("Safe header 'content-type' should be included in Access-Control-Allow-Headers")
					}
					if !foundAuthorization {
						t.Errorf("Safe header 'authorization' should be included in Access-Control-Allow-Headers")
					}
					if !foundCsrfToken {
						t.Errorf("Safe header 'x-csrf-token' should be included in Access-Control-Allow-Headers")
					}
				} else {
					t.Errorf("Expected Access-Control-Allow-Headers to be set for preflight request")
				}
			}
		})
	}
}

// Test that the middleware correctly validates configuration and panics when AllowCredentials=true with AllowOrigins=*
func TestCorsConfigValidation(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with AllowCredentials=true and AllowOrigins=*, but no panic occurred")
		}
	}()

	corsConfig := Config{
		AllowOrigins:     "*",
		AllowCredentials: true,
	}

	// This should panic
	New(corsConfig)
}

func TestCorsWithMultipleMiddleware(t *testing.T) {
	app := fiber.New()

	corsConfig := Config{
		AllowOrigins:     "https://example.com",
		AllowCredentials: true,
		AllowHeaders:     "Content-Type",
		ExposeHeaders:    "X-Custom",
		AllowMethods:     "GET, POST",
	}

	middlewareExecuted := false

	app.Use(func(c *fiber.Ctx) error {
		middlewareExecuted = true
		return c.Next()
	})

	app.Use(New(corsConfig))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to test request: %v", err)
	}

	if !middlewareExecuted {
		t.Error("Expected middleware to be executed")
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200 but got %d", resp.StatusCode)
	}

	origin := resp.Header.Get("Access-Control-Allow-Origin")
	if origin != "https://example.com" {
		t.Errorf("Expected Access-Control-Allow-Origin to be 'https://example.com' but got %q", origin)
	}
}

func TestCorsWithWildcardOrigin(t *testing.T) {
	app := fiber.New()

	corsConfig := Config{
		AllowOrigins:     "*",
		AllowCredentials: false, // Must be false with wildcard origin
		AllowHeaders:     "Content-Type",
		ExposeHeaders:    "X-Custom",
		AllowMethods:     "GET, POST",
	}

	app.Use(New(corsConfig))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	testOrigins := []string{
		"https://example.com",
		"https://another-site.com",
		"http://localhost:3000",
	}

	for _, origin := range testOrigins {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", origin)

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Failed to test request with origin %s: %v", origin, err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200 but got %d for origin %s", resp.StatusCode, origin)
		}

		respOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		if respOrigin != origin {
			t.Errorf("Expected Access-Control-Allow-Origin to be %q but got %q", origin, respOrigin)
		}
	}
}

func BenchmarkCorsMiddleware(b *testing.B) {
	app := fiber.New()

	corsConfig := Config{
		AllowOrigins:     "https://example.com, https://allowed.com",
		AllowCredentials: true,
		AllowHeaders:     "Content-Type",
		ExposeHeaders:    "X-Custom",
		AllowMethods:     "GET, POST, OPTIONS",
	}

	app.Use(New(corsConfig))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://allowed.com")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = app.Test(req)
	}
}
