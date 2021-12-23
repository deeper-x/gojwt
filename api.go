package gojwt

import (
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
func (jsess *JWTSess) Register(kval string) (bool, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	tokenString, err := newJWTToken(kval, expirationTime)
	if err != nil {
		return false, fmt.Errorf("Register::tokenString: %w", err)
	}

	http.SetCookie(jsess.RW, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	return true, nil
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
func (jsess *JWTSess) Refresh() (bool, error) {
	tknStr, err := readCookie(jsess.Req)
	if err != nil {
		log.Println(err)
		return false, err
	}

	tknValid, err := TokenIsValid(tknStr, &jsess.Claims)
	if err != nil {
		log.Println(err)
		return false, fmt.Errorf("Refresh::tknValid: %w", err)
	}

	if !tknValid {
		return false, nil
	}

	if isExpired(jsess.Claims) {
		return false, nil
	}

	newCookie, err := newToken(&jsess.Claims)
	if err != nil {
		return false, fmt.Errorf("Refresh::newCookie: %w", err)
	}

	http.SetCookie(jsess.RW, newCookie)
	return false, nil
}
