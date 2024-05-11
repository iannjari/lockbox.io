package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
	"github.com/lucsky/cuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		panic("unable to load env: " + err.Error())
	}

	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		panic("unable to open db: " + err.Error())
	}

	db.AutoMigrate(&Client{})

	// seed with dummy data
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "website", "redirect_uri", "logo"}),
	}).Create(&Client{
		ID:          "1",
		Name:        "client_1",
		Website:     "https://example.com",
		Logo:        "https://1000logos.net/wp-content/uploads/2016/11/New-Google-Logo.jpg",
		RedirectURI: "http://localhost:8000/auth/callback",
	})

	views := html.New("./views", ".html")

	api := fiber.New(fiber.Config{
		AppName: "lockbox.io",
		Views:   views,
	})

	// middleware
	api.Use(logger.New())
	api.Use(recover.New())

	api.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("hello 💙")
	})
	api.Get("/auth", func(c *fiber.Ctx) error {
		authRequest := new(AuthRequest)
		if c.QueryParser(authRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}

		if authRequest.ResponseType != "code" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid response type"})
		}
		if !strings.Contains(authRequest.RedirectURI, "https://") {
			return c.Status(400).JSON(fiber.Map{"error": "invalid redirect uri"})
		}
		if authRequest.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "inavlid client id"})
		}
		if authRequest.Scope == "" {
			return c.Status(400).JSON(fiber.Map{"error": "inavlid scope"})
		}

		// verify client exists
		client := new(Client)
		if err := db.Where("name = ?", authRequest.ClientID).First(&client).Error; err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "unknown client"})
		}

		// generate code
		code, err := cuid.NewCrypto(rand.Reader)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal server error"})
		}

		c.Cookie(&fiber.Cookie{
			Name:     "auth_request_code",
			Value:    code,
			Secure:   true,
			Expires:  time.Now().Add(2 * time.Minute),
			HTTPOnly: true,
		})

		return c.Render("authorize_page", fiber.Map{
			"Logo":    client.Logo,
			"Name":    client.Name,
			"Website": client.Website,
			"Scopes":  strings.Split(authRequest.Scope, " "),
		})

	})

	port := os.Getenv("PORT")
	if port == "" {
		panic("empty port!")
	}

	api.Listen(fmt.Sprintf(":%s", port))

}

type Client struct {
	ID          string `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex"`
	Website     string
	Logo        string
	RedirectURI string    `json:"redirect_uri"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	DeletedAt   time.Time `json:"-" gorm:"index"`
}

type AuthRequest struct {
	ResponseType string `json:"response_type" query:"response_type"`
	ClientID     string `json:"client_id" query:"client_id"`
	RedirectURI  string `json:"redirect_uri" query:"redirect_uri"`
	Scope        string
	State        string
}
