package gojwt

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Claims is a struct that contains the custom claims of the token
type Claims struct {
	jwt.StandardClaims
	Username string `json:"username"`
}

// newJWTToken retrieve current jwt token
func newJWTToken(username string, expirationTime time.Time) (string, error) {
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// TokenIsValid checks if the token is valid
func TokenIsValid(stoken string, claims *Claims) (bool, error) {
	tkn, err := jwt.ParseWithClaims(stoken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return false, err
	}

	return tkn.Valid, nil
}

// readCookie read cookie content
func readCookie(r *http.Request) (string, error) {
	c, err := r.Cookie("token")
	if err != nil {
		return "", err
	}

	return c.Value, nil
}

// isExpired check claims expiration
func isExpired(c Claims) bool {
	return time.Until(time.Unix(c.ExpiresAt, 0)) < 30*time.Second
}

// newToken set new token id and build cookie
func newToken(c *Claims) (*http.Cookie, error) {
	cookie := &http.Cookie{}
	expirationTime := time.Now().Add(5 * time.Minute)
	c.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		return cookie, err
	}

	return &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	}, nil
}
