package model

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID      `gorm:"primaryKey" json:"id"`
	FirstName string         `gorm:"uniqueIndex" json:"first_name"`
	LastName  string         `gorm:"uniqueIndex" json:"last_name"`
	Email     string         `gorm:"uniqueIndex" json:"email"`
	Password  string         `json:"-"`
	Code      sql.NullString `gorm:"default:null"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt time.Time      `json:"-" gorm:"index"`
}

type CreateUserRequest struct {
	FirstName string `gorm:"uniqueIndex" json:"first_name"`
	LastName  string `gorm:"uniqueIndex" json:"last_name"`
	Email     string `gorm:"uniqueIndex" json:"email"`
	Password  string `json:"password"`
}
