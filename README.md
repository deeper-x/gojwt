### GOJWT 


Implementation example:

```go
func main() {
	http.HandleFunc("/signin", Login)
	http.HandleFunc("/protected_content", ProtectedContent)
	http.HandleFunc("/refresh", Renew)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

// Login index login
func Login(w http.ResponseWriter, req *http.Request) {
	jsess := gojwt.NewJWTSess(w, req)

	var creds gojwt.Credentials

	err := json.NewDecoder(jsess.Req.Body).Decode(&creds)
	if err != nil {
		log.Println(err)
		jsess.RW.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword := "password1"

	if expectedPassword != creds.Password {
		jsess.RW.WriteHeader(http.StatusUnauthorized)
		return
	}

	ok, err := jsess.Register(creds.Username)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// success
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user registered"))
}

// ProtectedContent is the registered users only content
func ProtectedContent(w http.ResponseWriter, req *http.Request) {
	jsess := gojwt.NewJWTSess(w, req)

	ok, err := jsess.IsAllowed()
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
	w.Write([]byte("REGISTERED CONTENT"))
}

// Renew ask for new token
func Renew(w http.ResponseWriter, req *http.Request) {
	jsess := gojwt.NewJWTSess(w, req)

	ok, err := jsess.Refresh()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("token cannot still be renewed"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("token renewed"))
}
```