package handler

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"lockbox.io/model"
)

func RegisterUser(c *fiber.Ctx) error {

	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		panic("unable to open db: " + err.Error())
	}
	userReq := new(model.CreateUserRequest)
	if err := c.BodyParser(userReq); err != nil {
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

	user := model.User{
		ID:        uuid.New(),
		FirstName: userReq.FirstName,
		LastName:  userReq.LastName,
		Email:     userReq.Email,
		Password:  string(hashedPassword),
	}

	db.Create(&user)

	return c.Status(200).JSON(fiber.Map{"status": "sucess", "message": "created user", "data": user})

}
