package gojwt

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// JWTSess is the object used for session management
type JWTSess struct {
	RW     http.ResponseWriter
	Req    *http.Request
	Claims Claims
}

// NewJWTSess is the JWTSess builder
func NewJWTSess(w http.ResponseWriter, req *http.Request) *JWTSess {
	c := Claims{}
	return &JWTSess{
		Claims: c,
		RW:     w,
		Req:    req,
	}
}

//Register Create the Register handler
func (jsess *JWTSess) Register(kval string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	tokenString, err := newJWTToken(kval, expirationTime)
	if err != nil {
		return "", fmt.Errorf("Register::tokenString: %w", err)
	}

	http.SetCookie(jsess.RW, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	return tokenString, nil
}

// IsAllowed is the handler that will be called when a user calls the `/` endpoint
func (jsess *JWTSess) IsAllowed() (bool, error) {
	tknStr, err := readCookie(jsess.Req)
	if err != nil {
		return false, err
	}

	tknValid, err := TokenIsValid(tknStr, &jsess.Claims)
	if err != nil {
		return false, fmt.Errorf("IsAllowed::tknValid: %w", err)
	}

	if !tknValid {
		return false, nil
	}

	return true, nil
}

// Refresh is the handler that will be called when a user calls the `/refresh` endpoint
func (jsess *JWTSess) Refresh() (string, error) {
	tknStr, err := readCookie(jsess.Req)
	if err != nil {
		log.Println(err)
		return "", err
	}

	tknValid, err := TokenIsValid(tknStr, &jsess.Claims)
	if err != nil {
		log.Println(err)
		return "", fmt.Errorf("Refresh::tknValid: %w", err)
	}

	if !tknValid {
		return "", errors.New("token not valid")
	}

	if isExpired(jsess.Claims) {
		return "", errors.New("token expired")
	}

	newCookie, err := newToken(&jsess.Claims)
	if err != nil {
		return "", fmt.Errorf("Refresh::newCookie: %w", err)
	}

	// setting cookie
	http.SetCookie(jsess.RW, newCookie)

	token := newCookie.Value
	return token, nil
}
