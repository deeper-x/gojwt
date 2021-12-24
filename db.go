package gojwt

// Credentials is a struct user to map the username and password to the request body
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

var testusers = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

var jwtKey = []byte("change_me")
