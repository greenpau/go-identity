package identity

import (
	"math/rand"
	"strings"
)

// NewID returns a random ID to be used for user identification.
func NewID() string {
	chars := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	length := 32
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}
