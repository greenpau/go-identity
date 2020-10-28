package identity

import (
	"github.com/satori/go.uuid"
	"math/rand"
	"strings"
)

// NewID returns a random ID to be used for user identification.
func NewID() string {
	return uuid.NewV4().String()

	/*
		if err != nil {
			return u4.String()
		}
		chars := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
		length := 32
		var b strings.Builder
		for i := 0; i < length; i++ {
			b.WriteRune(chars[rand.Intn(len(chars))])
		}
		return b.String()
	*/
}

// NewRandomString returns a random string.
func NewRandomString(length int) string {
	chars := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	if length == 0 {
		length = 32
	}
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}
