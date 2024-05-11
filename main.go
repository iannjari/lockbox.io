package main

import (
	"os"
	"time"

	"github.com/joho/godotenv"
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
		Logo:        "https://en.wikipedia.org/wiki/File:Logo_sample.png",
		RedirectURI: "http://localhost:8000/auth/callback",
	})

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
