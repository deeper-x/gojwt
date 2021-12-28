package gojwt

import (
	"errors"
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
func (jsess *JWTSess) Register(kval string, durmins time.Duration) (string, error) {
	expirationTime := time.Now().Add(durmins * time.Minute)

	tokenString, err := newJWTToken(kval, expirationTime)
	if err != nil {
		return "", err
	}

	http.SetCookie(jsess.RW, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	return tokenString, nil
}

// IsAuth check if client is allowed
func (jsess *JWTSess) IsAuth() (bool, error) {
	tknStr, err := readCookie(jsess.Req)
	if err != nil {
		return false, err
	}

	tknValid, err := TokenIsValid(tknStr, &jsess.Claims)
	if err != nil {
		return false, err
	}

	if !tknValid {
		return false, errors.New("token not valid in auth")
	}

	return true, nil
}

// Renew ask for a new token
func (jsess *JWTSess) Renew() (string, error) {
	tknStr, err := readCookie(jsess.Req)
	if err != nil {
		return "", err
	}

	tknValid, err := TokenIsValid(tknStr, &jsess.Claims)
	if err != nil {
		return "", err
	}

	if !tknValid {
		return "", errors.New("token cannt be renewed")
	}

	if !isExpiring(jsess.Claims) {
		return "", errors.New("token not expired")
	}

	newCookie, err := newToken(&jsess.Claims)
	if err != nil {
		return "", errors.New("token cannt be generated")
	}

	// setting cookie
	http.SetCookie(jsess.RW, newCookie)

	token := newCookie.Value
	return token, nil
}
