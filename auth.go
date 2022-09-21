package auth

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"

	"net/http"
)

type KeyPair struct {
	Key   string
	Value string
}

type Authorization interface {
	// HeaderKey is the key to use for the Authorization header.
	HeaderKey() string
	// Valid validates if the header is valid
	Valid(string) (bool, []KeyPair)
	//Create a new Authorization Header
	Header() string
}

type Auth struct {
	Authorization []Authorization
}

func NewAuth(auth ...Authorization) *Auth {
	return &Auth{
		Authorization: auth,
	}
}

func (a *Auth) Add(auth Authorization) {
	a.Authorization = append(a.Authorization, auth)
}

func (a *Auth) GinMiddleware(c *gin.Context) {
	for _, auth := range a.Authorization {
		authorized, keypairs := auth.Valid(c.GetHeader(auth.HeaderKey()))
		if authorized {
			for _, keypair := range keypairs {
				c.Set(keypair.Key, keypair.Value)
			}
			return
		}
	}
	c.AbortWithStatus(http.StatusUnauthorized)
	return
}
func (a *Auth) EchoMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		for _, auth := range a.Authorization {
			authorized, keypairs := auth.Valid(c.Request().Header.Get(auth.HeaderKey()))
			if authorized {
				for _, keypair := range keypairs {
					c.Set(keypair.Key, keypair.Value)
				}
				return next(c)
			}
		}
		return echo.ErrUnauthorized
	}
}

type BasicAuth struct {
	Username string
	Password string
}

func (a *BasicAuth) HeaderKey() string {
	return "Authorization"
}

func (a *BasicAuth) Valid(auth string) (bool, []KeyPair) {
	return auth == a.Header(), []KeyPair{{"user", a.Username}}
}

func (a *BasicAuth) Header() string {
	base := a.Username + ":" + a.Password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(base))
}

type APIKeyAuth struct {
	Token string
	User  string
}

func (a *APIKeyAuth) HeaderKey() string {
	return "X-Api-Key"
}

func (a *APIKeyAuth) Valid(auth string) (bool, []KeyPair) {
	return auth == a.Token, []KeyPair{{"user", a.User}}
}

func (a *APIKeyAuth) Header() string {
	return a.Token
}
