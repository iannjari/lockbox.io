package handler

import (
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"lockbox.io/model"
)

func GetClientToken(c *fiber.Ctx) error {
	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "internal server error, code: ERR4000"})
	}

	getClientTokenReq := new(model.GetClientTokenRequest)

	if err := c.BodyParser(getClientTokenReq); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "internal server error, code: ERR4001"})
	}

	if getClientTokenReq.ClientId == "" || getClientTokenReq.ClientSecret == "" || getClientTokenReq.GrantType != "client_credentials" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request, code: ERR4002"})
	}

	// verify client exists
	client := new(model.Client)
	if err := db.Where("name = ?", getClientTokenReq.ClientId).First(&client).Error; err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "invalid client/secret pair, code: ERR4003"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(getClientTokenReq.ClientSecret)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "invalid client/secret pair, code: ERR4004"})
	}

	// generate token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["iss"] = c.BaseURL()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 5).Unix()
	claims["username"] = client.Name
	claims["identity"] = client.ID
	claims["sub"] = client.ID
	claims["type"] = "Bearer"
	claims["azp"] = "frontend"
	claims["entity_roles"] = client

	accessToken, err := token.SignedString([]byte(client.ClientSecret))

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal server error, code: ERR4005"})
	}

	tokenResponse := model.TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   18000,
		TokenType:   "Bearer",
	}

	return c.Status(200).JSON(tokenResponse)
}
