package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/lucsky/cuid"
	"golang.org/x/crypto/bcrypt"
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

	db.AutoMigrate(&Client{}, &User{})

	// generate code
	clientSecret, err := cuid.NewCrypto(rand.Reader)
	if err != nil {
		panic("internal server error generating example client id")
	}

	// seed with dummy data
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "website", "redirect_uri", "logo", "client_secret"}),
	}).Create(&Client{
		ID:           uuid.New(),
		Name:         "client_1",
		Website:      "https://example.com",
		Logo:         "https://1000logos.net/wp-content/uploads/2016/11/New-Google-Logo.jpg",
		RedirectURI:  "http://localhost:8000/auth/callback",
		ClientSecret: clientSecret,
	})

	views := html.New("./views", ".html")

	api := fiber.New(fiber.Config{
		AppName: "lockbox.io",
		Views:   views,
	})

	// middleware
	api.Use(logger.New())
	api.Use(recover.New())
	api.Use(favicon.New(favicon.Config{
		File: "./media/favicon.ico",
		URL:  "/favicon.ico",
	}))

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
			return c.Status(400).JSON(fiber.Map{"error": "invalid client id"})
		}
		if authRequest.Scope == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid scope"})
		}
		if authRequest.State == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid state"})
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
			Name:     "temp_auth_request_code",
			Value:    code,
			Secure:   true,
			Expires:  time.Now().Add(2 * time.Minute),
			HTTPOnly: true,
		})

		return c.Render("authorize_page", fiber.Map{
			"Logo":    client.Logo,
			"Name":    client.Name,
			"Website": client.Website,
			"State":   authRequest.State,
			"Scopes":  strings.Split(authRequest.Scope, " "),
		})

	})

	api.Get("/confirm_auth", func(c *fiber.Ctx) error {
		tempCode := c.Cookies("temp_auth_request_code")
		if tempCode == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid temp auth code"})
		}
		c.ClearCookie("temp_auth_request_code")

		authConfirmReq := new(ConfirmAuthRequest)
		if c.QueryParser(authConfirmReq); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}

		// verify client exists
		client := new(Client)
		if err := db.Where("name = ?", authConfirmReq.ClientID).First(&client).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "unknown client"})
		}

		if !authConfirmReq.Authorize {
			return c.Redirect(client.RedirectURI + "?error=access_denied" + "&state=" + authConfirmReq.State)
		}

		// save generated auth code
		db.Model(&client).Update("code", tempCode)

		return c.Redirect(client.RedirectURI + "?code=" + tempCode + "&state=" + authConfirmReq.State)
	})

	api.Post("/user", func(c *fiber.Ctx) error {
		userReq := new(CreateUserRequest)
		if c.BodyParser(userReq); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}

		if userReq.FirstName == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid first name"})
		}
		if userReq.LastName == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid last name"})
		}
		if userReq.Email == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid email"})
		}
		if userReq.Password == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid password"})
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userReq.Password), 14)
		if err != nil {
			log.Print(err.Error())
			return c.Status(400).JSON(fiber.Map{"error": "invalid password"})
		}

		user := User{
			ID:        uuid.New(),
			FirstName: userReq.FirstName,
			LastName:  userReq.LastName,
			Email:     userReq.Email,
			Password:  string(hashedPassword),
		}

		db.Create(&user)

		return c.Status(200).JSON(fiber.Map{"status": "sucess", "message": "created user", "data": user})

	})

	api.Get("/token", func(c *fiber.Ctx) error {
		tokenReq := new(TokenRequest)
		if c.BodyParser(tokenReq); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}

		if !strings.Contains(tokenReq.RedirectURI, "https://") {
			return c.Status(400).JSON(fiber.Map{"error": "invalid redirect uri"})
		}
		if tokenReq.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid client id"})
		}
		if tokenReq.ClientSecret == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid client secret"})
		}
		if tokenReq.GrantType == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid grant type"})
		}
		if tokenReq.Code == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid code"})
		}

		// verify client exists
		client := new(Client)
		if err := db.Where("name = ?", tokenReq.ClientID).First(&client).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "unknown client"})
		}

		// validate code
		if !client.Code.Valid {
			return c.Status(500).JSON(fiber.Map{"error": "invalid code"})
		}
		if tokenReq.Code != client.Code.String {
			return c.Status(500).JSON(fiber.Map{"error": "invalid code"})
		}

		// generate token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)

		claims["username"] = client.Name
		claims["user_id"] = client.ID
		claims["exp"] = time.Now().Add(time.Hour * 5).Unix()

		accessToken, err := token.SignedString([]byte(client.ClientSecret))

		if err != nil {
			log.Fatal(err.Error())
			return c.Status(500).JSON(fiber.Map{"error": "error while signing token"})
		}

		tokenResponse := TokenResponse{
			AccessToken: accessToken,
			ExpiresIn:   18000,
		}

		return c.Status(200).JSON(tokenResponse)

	})

	port := os.Getenv("PORT")
	if port == "" {
		panic("empty port!")
	}

	api.Listen(fmt.Sprintf("localhost:%s", port))

}

type Client struct {
	ID           uuid.UUID `gorm:"primaryKey"`
	Name         string    `gorm:"uniqueIndex" json:"client_id"`
	Website      string
	Logo         string
	Code         sql.NullString `gorm:"default:null"`
	RedirectURI  string         `json:"redirect_uri"`
	ClientSecret string         `json:"-"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    time.Time      `json:"-" gorm:"index"`
}

type User struct {
	ID        uuid.UUID `gorm:"primaryKey" json:"id"`
	FirstName string    `gorm:"uniqueIndex" json:"first_name"`
	LastName  string    `gorm:"uniqueIndex" json:"last_name"`
	Email     string    `gorm:"uniqueIndex" json:"email"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	DeletedAt time.Time `json:"-" gorm:"index"`
}

type CreateUserRequest struct {
	FirstName string `gorm:"uniqueIndex" json:"first_name"`
	LastName  string `gorm:"uniqueIndex" json:"last_name"`
	Email     string `gorm:"uniqueIndex" json:"email"`
	Password  string `json:"password"`
}

type AuthRequest struct {
	ResponseType string `json:"response_type" query:"response_type"`
	ClientID     string `json:"client_id" query:"client_id"`
	RedirectURI  string `json:"redirect_uri" query:"redirect_uri"`
	Scope        string
	State        string
}

type ConfirmAuthRequest struct {
	Authorize bool   `json:"authorize" query:"authorize"`
	ClientID  string `json:"client_id" query:"client_id"`
	State     string
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}
