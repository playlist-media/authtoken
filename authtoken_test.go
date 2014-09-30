package authtoken

import (
	"testing"
	"time"
)

func TestNewToken(t *testing.T) {
	token := NewToken("test", time.Unix(0, 0), []byte("secret"))

	if token != "AAAAAHRlc3QaqjaR5RjUthn9sKAVsiOBRvY2TzmKghyJ3IsJfNcq-A==" {
		t.Fatalf("Failed to create new token, expected AAAAAHRlc3QaqjaR5RjUthn9sKAVsiOBRvY2TzmKghyJ3IsJfNcq-A==, got %v", token)
	}
}

func TestExpiration(t *testing.T) {
	secret := []byte("secret")
	exp := time.Unix(0, 0)
	token := NewToken("test", exp, secret)
	login := TokenLogin(token, secret)

	if login != "" {
		t.Fatalf("Failed to expire token")
	}
}

func TestTokenLogin(t *testing.T) {
	secret := []byte("secret")
	exp := time.Now().Add(5 * time.Minute)
	token := NewToken("test", exp, secret)
	login := TokenLogin(token, secret)

	if login != "test" {
		t.Fatalf("Failed to get login, expected test, got %v", login)
	}
}
