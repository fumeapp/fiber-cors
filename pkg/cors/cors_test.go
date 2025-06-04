package cors

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestCorsMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		requestOrigin  string
		requestMethod  string
		expectedOrigin string
		expectedStatus int
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
			expectedOrigin: "",
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
			name: "empty config",
			config: Config{
				AllowOrigins:     "",
				AllowCredentials: false,
				AllowHeaders:     "",
				ExposeHeaders:    "",
				AllowMethods:     "",
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
		})
	}
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
		AllowCredentials: true,
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
