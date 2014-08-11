package authtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

const (
	decodedMinLength = 4 + 1 + 32
	decodedMaxLength = 1024
)

func getSignature(b []byte, secret []byte) []byte {
	key := hmac.New(sha256.New, secret)
	key.Write(b)
	m := hmac.New(sha256.New, key.Sum(nil))
	m.Write(b)
	return m.Sum(nil)
}

var (
	ErrMalformedToken      = errors.New("malformed token")
	ErrWrongTokenSignature = errors.New("wrong token signature")
)

// NewToken returns a signed auth token for the given login, expiration time,
// and secret key.  If the login is empty, the function returns an
// empty string.
func NewToken(login string, expires time.Time, secret []byte) string {
	if login == "" {
		return ""
	}

	llen := len(login)
	b := make([]byte, llen+4+32)
	binary.BigEndian.PutUint32(b, uint32(expires.Unix()))
	copy(b[4:], []byte(login))
	sig := getSignature([]byte(b[:4+llen]), secret)
	copy(b[4+llen:], sig)
	return base64.URLEncoding.EncodeToString(b)
}

// NewTokenFromNow returns a signed auth token for the given login, duration
// since the current time, and secret key.
func NewTokenFromNow(login string, dur time.Duration, secret []byte) string {
	return NewToken(login, time.Now().Add(dur), secret)
}

func ParseToken(token string, secret []byte) (login string, expires time.Time, err error) {
	blen := base64.URLEncoding.DecodedLen(len(token))
	if blen < decodedMinLength || blen > decodedMaxLength {
		err = ErrMalformedToken
		return
	}

	b, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return
	}

	blen = len(b)
	if blen < decodedMinLength {
		err = ErrMalformedToken
		return
	}
	b = b[:blen]

	sig := b[blen-32:]
	data := b[:blen-32]

	realSig := getSignature(data, secret)
	if subtle.ConstantTimeCompare(realSig, sig) != 1 {
		err = ErrWrongTokenSignature
		return
	}

	expires = time.Unix(int64(binary.BigEndian.Uint32(data[:4])), 0)
	login = string(data[4:])
	return
}

func TokenLogin(token string, secret []byte) string {
	l, exp, err := ParseToken(token, secret)
	if err != nil || exp.Before(time.Now()) {
		return ""
	}
	return l
}
