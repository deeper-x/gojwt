### GOJWT 

installation:
```bash
go get -v github.com/deeper-x/gojwt
```

Implementation example:

```go
func main() {
	http.HandleFunc("/signin", Login)
	http.HandleFunc("/protected_content", ProtectedContent)
	http.HandleFunc("/renew", Renew)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

// Login index login, with username and password in the body of a GET request
func Login(w http.ResponseWriter, req *http.Request) {
	jsess := gojwt.NewJWTSess(w, req)

	var creds gojwt.Credentials

	err := json.NewDecoder(jsess.Req.Body).Decode(&creds)
	if err != nil {
		log.Println(err)
		jsess.RW.WriteHeader(http.StatusBadRequest)
		return
	}

	// check fake credentials
	expectedPassword := "password1"

	if expectedPassword != creds.Password {
		jsess.RW.WriteHeader(http.StatusUnauthorized)
		return
	}

	// client registration
	token, err := jsess.Register(creds.Username)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// success
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

// ProtectedContent is the registered-users-only content
func ProtectedContent(w http.ResponseWriter, req *http.Request) {
	jsess := gojwt.NewJWTSess(w, req)

	ok, err := jsess.IsAuth()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("WELCOME, THIS IS A SECRET CONTENT\n\n"))
}

// Renew ask for a new token, if available
func Renew(w http.ResponseWriter, req *http.Request) {
	jsess := gojwt.NewJWTSess(w, req)

	token, err := jsess.Renew()
	if err != nil {
		log.Println(err)

		// no token released
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Token cannot be renewed\n\n"))
		return
	}

	// token released
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

```

Client example:

```bash
# registration
curl --location --request GET 'http://127.0.0.1:8000/signin' --header 'Content-Type: text/plain' --data-raw '{"username": "user1", "password": "password1"}'

# accessing *protected* content
curl --location --request GET 'http://127.0.0.1:8000/protected_content' --header 'Cookie: token=<YOUR_TOKEN>'

# renew
curl --location --request GET 'http://127.0.0.1:8000/refresh' --header 'Cookie: token=<YOUR_TOKEN>'

```