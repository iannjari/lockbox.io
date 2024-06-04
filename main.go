package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/lucsky/cuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"lockbox.io/handler"
	"lockbox.io/model"
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

	db.AutoMigrate(&model.Client{}, &model.User{})

	// generate code
	clientSecret, err := cuid.NewCrypto(rand.Reader)
	if err != nil {
		panic("internal server error generating example client id")
	}

	// seed with dummy data
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "website", "redirect_uri", "logo", "client_secret"}),
	}).Create(&model.Client{
		ID:           uuid.New(),
		Name:         "client_1",
		Website:      "https://example.com",
		Logo:         "https://1000logos.net/wp-content/uploads/2016/11/New-Google-Logo.jpg",
		RedirectURI:  "https://google.com",
		ClientSecret: clientSecret,
	})

	views := html.New("./views", ".html")

	api := fiber.New(fiber.Config{
		AppName: "lockbox.io",
		Views:   views,
	})

	api.Static("/public", "./public")

	// middleware
	api.Use(logger.New())
	api.Use(recover.New())
	api.Use(favicon.New(favicon.Config{
		File: "./public/favicon.ico",
		URL:  "/favicon.ico",
	}))

	// register routes + handlers
	api.Get("/", handler.Hello)
	api.Get("/auth", handler.Login)
	api.Get("/confirm_auth", handler.ConfirmAuth)
	api.Post("/user", handler.RegisterUser)
	api.Get("/token", handler.GetToken)
	api.Get("/redirect", handler.RedirectOrLogin)

	port := os.Getenv("PORT")
	if port == "" {
		panic("empty port!")
	}

	api.Listen(fmt.Sprintf("localhost:%s", port))

}
