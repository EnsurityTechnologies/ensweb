package main

import (
	"strings"
	"time"

	"github.com/EnsurityTechnologies/ensweb"
	"github.com/EnsurityTechnologies/logger"
	"github.com/EnsurityTechnologies/uuid"
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
)

const (
	UserTable string = "UserTable"
)

type Model struct {
	db  *gorm.DB
	log logger.Logger
}

// Base contains common columns for all tables.
type Base struct {
	ID                   uuid.UUID `gorm:"column:ID;primaryKey;"`
	CreationTime         time.Time `gorm:"column:CreationTime;not null"`
	CreatorID            uuid.UUID `gorm:"column:CreatorId"`
	LastModificationTime time.Time `gorm:"column:LastModificationTime"`
	LastModifierID       uuid.UUID `gorm:"column:LastModifierId"`
	TenantID             uuid.UUID `gorm:"column:TenantId"`
}

type User struct {
	Base
	UserName string `gorm:"column:UserName"`
	Password string `gorm:"column:Password"`
}

type Request struct {
	UserName string `json:"email"`
	Password string `json:"password"`
}

type Response struct {
	ensweb.BaseResponse
	Token string `json:"token"`
}

type Token struct {
	UserName string `json:"UserName"`
	jwt.StandardClaims
}

// // BeforeCreate will set a UUID rather than numeric ID.
// func (base *Base) BeforeCreate(scope *gorm.Scope) error {
// 	uuid := uuid.New()

// 	err := scope.SetColumn("CreationTime", time.Now())
// 	if err != nil {
// 		return err
// 	}
// 	return scope.SetColumn("ID", uuid)
// }

// // BeforeCreate will set a UUID rather than numeric ID.
// func (base *Base) BeforeUpdate(scope *gorm.Scope) error {
// 	return scope.SetColumn("LastModificationTime", time.Now())
// }

// BeforeCreate will set a UUID rather than numeric ID.
func (b *Base) BeforeCreate(tx *gorm.DB) error {
	uuid := uuid.New()
	tx.Statement.SetColumn("CreationTime", time.Now())
	tx.Statement.SetColumn("ID", uuid)
	return nil
}

// BeforeCreate will set a UUID rather than numeric ID.
func (b *Base) BeforeUpdate(tx *gorm.DB) error {
	tx.Statement.SetColumn("LastModificationTime", time.Now())
	return nil
}

// BeforeCreate will set a UUID rather than numeric ID.
func (b *Base) BeforeSave(tx *gorm.DB) error {
	tx.Statement.SetColumn("LastModificationTime", time.Now())
	return nil
}

func NewModel(db *gorm.DB, log logger.Logger) (*Model, error) {
	m := &Model{
		db:  db,
		log: log,
	}
	err := db.AutoMigrate(&User{})
	if err != nil {
		return nil, err
	}
	user := m.GetUser(uuid.Nil, "admin")
	if user == nil {
		user = &User{
			UserName: "admin",
			Password: "123456",
		}
		err = m.CreateUser(user)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

// GetUser get user
func (m *Model) GetUser(TenantID uuid.UUID, userName string) *User {
	var user User
	err := m.db.Find(&user, "UserName=?", strings.ToLower(userName)).Error
	if err != nil {
		return nil
	}
	if user.UserName != strings.ToLower(userName) {
		return nil
	}
	return &user
}

// CreateUser create user
func (m *Model) CreateUser(user *User) error {
	err := m.db.Create(user).Error
	return err
}
