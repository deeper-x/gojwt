package gojwt

import (
	"net/http"
	"time"
)

// JWTSess is the object used for session management
type JWTSess struct {
	RW     http.ResponseWriter
	Req    *http.Request
	Claims Claims
}

// Status is the object describining http outcomes
type Status struct {
	Code    int64
	Message string
	Success bool
	Error   error
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

// NewStatus is the result object, with all describing fields
func NewStatus(cod int64, msg string, sts bool, err error) Status {
	return Status{
		Code:    cod,
		Message: msg,
		Success: sts,
		Error:   err,
	}
}

//Register Create the Register handler
func (jsess *JWTSess) Register(kval string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

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
func (jsess *JWTSess) IsAuth() (bool, Status) {
	tknStr, sts := readCookie(jsess.Req)
	if sts.Error != nil {
		return false, sts
	}

	tknValid, sts := TokenIsValid(tknStr, &jsess.Claims)
	if sts.Error != nil {
		return false, sts
	}

	if !tknValid {
		sts = NewStatus(TKNBROKEN, "token broken", false, nil)
		return false, sts
	}

	return true, sts
}

// Renew ask for a new token
func (jsess *JWTSess) Renew() (string, Status) {
	tknStr, sts := readCookie(jsess.Req)
	if sts.Error != nil {
		return "", sts
	}

	tknValid, sts := TokenIsValid(tknStr, &jsess.Claims)
	if sts.Error != nil {
		return "", sts
	}

	if !tknValid {
		sts = NewStatus(INVALIDTKN, "token not valid, cannot be updated", false, nil)
		return "", sts
	}

	if !isExpired(jsess.Claims) {
		sts = NewStatus(TKNSTILLVALID, "token not expiring, cannot be updated", false, nil)
		return "", sts
	}

	newCookie, sts := newToken(&jsess.Claims)
	if sts.Error != nil {
		return "", sts
	}

	// setting cookie
	http.SetCookie(jsess.RW, newCookie)

	token := newCookie.Value
	return token, sts
}
