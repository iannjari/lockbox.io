package handler

import (
	"crypto/rand"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucsky/cuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"lockbox.io/model"
)

func Hello(c *fiber.Ctx) error {
	return c.SendString("hello 💙")
}

func Login(c *fiber.Ctx) error {
	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR1000",
		})
	}
	authRequest := new(model.AuthRequest)
	if err := c.QueryParser(authRequest); err != nil {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR1001",
		})
	}

	if authRequest.ResponseType != "code" {
		return c.Render("internal_error", fiber.Map{
			"EntryPoint":  c.OriginalURL(),
			"ErrorCode":   "ERR1002",
			"RedirectURI": authRequest.RedirectURI,
		})
	}
	if !strings.Contains(authRequest.RedirectURI, "https://") {
		return c.Render("internal_error", fiber.Map{
			"EntryPoint":  c.OriginalURL(),
			"RedirectURI": authRequest.RedirectURI,
			"ErrorCode":   "ERR1003",
		})
	}
	if authRequest.ClientID == "" {
		return c.Render("internal_error", fiber.Map{
			"RedirectURI": authRequest.RedirectURI,
			"EntryPoint":  c.OriginalURL(),
			"ErrorCode":   "ERR1004",
		})
	}
	if authRequest.Scope == "" {
		return c.Render("internal_error", fiber.Map{
			"RedirectURI": authRequest.RedirectURI,
			"EntryPoint":  c.OriginalURL(),
			"ErrorCode":   "ERR1005",
		})
	}
	if authRequest.State == "" {
		return c.Render("internal_error", fiber.Map{
			"RedirectURI": authRequest.RedirectURI,
			"EntryPoint":  c.OriginalURL(),
			"ErrorCode":   "ERR1006",
		})
	}

	// verify client exists
	client := new(model.Client)
	if err := db.Where("name = ?", authRequest.ClientID).First(&client).Error; err != nil {
		return c.Render("internal_error", fiber.Map{
			"RedirectURI": authRequest.RedirectURI,
			"EntryPoint":  c.OriginalURL(),
			"ErrorCode":   "ERR1007",
		})
	}

	// generate code
	code, err := cuid.NewCrypto(rand.Reader)
	if err != nil {
		return c.Render("internal_error", fiber.Map{
			"RedirectURI": authRequest.RedirectURI,
			"EntryPoint":  c.OriginalURL(),
			"ErrorCode":   "ERR1008",
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "temp_auth_request_code",
		Value:    code,
		Secure:   true,
		Expires:  time.Now().Add(2 * time.Minute),
		HTTPOnly: true,
	})

	return c.Render("authorize_page", fiber.Map{
		"RedirectURI": authRequest.RedirectURI,
		"Name":        client.Name,
		"Website":     client.Website,
		"State":       authRequest.State,
		"Scopes":      strings.Split(authRequest.Scope, " "),
		"EntryPoint":  c.OriginalURL(),
	})

}

func RedirectOrLogin(c *fiber.Ctx) error {
	redirectReq := new(model.RedirectOrLoginRequest)
	if err := c.QueryParser(redirectReq); err != nil {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR3000",
		})
	}
	if redirectReq.ClientRedirectURI == "" {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR3001",
		})
	}
	if redirectReq.EntryPoint == "" {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR3002",
		})
	}

	if redirectReq.RedirectToOrigin {
		return c.Redirect(redirectReq.ClientRedirectURI + "?error=access_denied" + "&state=" + redirectReq.State)
	} else {
		return c.Redirect(redirectReq.EntryPoint)
	}
}

func ConfirmAuth(c *fiber.Ctx) error {
	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR2000",
		})
	}
	tempCode := c.Cookies("temp_auth_request_code")
	if tempCode == "" {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR2001",
		})
	}
	c.ClearCookie("temp_auth_request_code")

	authConfirmReq := new(model.ConfirmAuthRequest)
	if err := c.QueryParser(authConfirmReq); err != nil {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR2002",
		})
	}

	if authConfirmReq.Identity == "" || authConfirmReq.ClientID == "" || authConfirmReq.Password == "" {
		return c.Render("invalid_creds", fiber.Map{
			"RedirectURI": authConfirmReq.ClientRedirectURI,
			"State":       authConfirmReq.State,
			"EntryPoint":  authConfirmReq.EntryPoint,
		})
	}

	// verify client exists
	client := new(model.Client)
	if err := db.Where("name = ?", authConfirmReq.ClientID).First(&client).Error; err != nil {
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR2003",
		})
	}

	// redirect with access denied
	if !authConfirmReq.Authorize {
		return c.Redirect(authConfirmReq.ClientRedirectURI + "?error=access_denied" + "&state=" + authConfirmReq.State)
	}

	// fetch user
	user := new(model.User)
	if err := db.Where("email = ?", authConfirmReq.Identity).First(&user).Error; err != nil {
		println(err.Error)
		return c.Render("internal_error2", fiber.Map{
			"ErrorCode": "ERR2004",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(authConfirmReq.Password)); err != nil {
		return c.Render("invalid_creds", fiber.Map{
			"RedirectURI": authConfirmReq.ClientRedirectURI,
			"State":       authConfirmReq.State,
			"EntryPoint":  authConfirmReq.EntryPoint,
		})
	}

	// save generated auth code
	db.Model(&user).Update("code", tempCode)

	return c.Redirect(authConfirmReq.ClientRedirectURI + "?code=" + tempCode + "&state=" + authConfirmReq.State)
}

func GetToken(c *fiber.Ctx) error {
	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		panic("unable to open db: " + err.Error())
	}
	tokenReq := new(model.TokenRequest)
	if err := c.BodyParser(tokenReq); err != nil {
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
	client := new(model.Client)
	if err := db.Where("name = ?", tokenReq.ClientID).First(&client).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "unknown client"})
	}

	// verify user exists
	user := new(model.User)
	if err := db.Where("code = ?", client.Code.String).First(&user).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "unknown user"})
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

	tokenResponse := model.TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   18000,
	}

	return c.Status(200).JSON(tokenResponse)
}
