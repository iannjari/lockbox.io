package model

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type AuthRequest struct {
	ResponseType string `json:"response_type" query:"response_type"`
	ClientID     string `json:"client_id" query:"client_id"`
	RedirectURI  string `json:"redirect_uri" query:"redirect_uri"`
	Scope        string
	State        string
}

type ConfirmAuthRequest struct {
	Identity          string `json:"identity"`
	Password          string `json:"password"`
	Authorize         bool   `json:"authorize" query:"authorize"`
	ClientID          string `json:"client_id" query:"client_id"`
	ClientRedirectURI string `json:"redirect_uri" query:"redirect_uri"`
	EntryPoint        string `json:"entry_point" query:"entry_point"`
	State             string
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
	TokenType   string `json:"token_type"`
}

type Client struct {
	ID           uuid.UUID `gorm:"primaryKey"`
	Name         string    `gorm:"uniqueIndex" json:"client_id"`
	Website      string
	Logo         string
	Code         sql.NullString `gorm:"default:null" json:"-"`
	RedirectURI  string         `json:"redirect_uri"`
	ClientSecret string         `json:"-"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    time.Time      `json:"-" gorm:"index"`
}

type RedirectOrLoginRequest struct {
	ClientRedirectURI string `json:"redirect_uri" query:"redirect_uri"`
	State             string `json:"state" query:"state"`
	EntryPoint        string `json:"entry_point" query:"entry_point"`
	RedirectToOrigin  bool   `json:"redirect_to_origin" query:"redirect_to_origin"`
}

type GetClientTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}
