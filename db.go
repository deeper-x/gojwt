package gojwt

// Credentials is a struct to read the username and password from the request body
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

var testusers = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

var jwtKey = []byte("change_me")
