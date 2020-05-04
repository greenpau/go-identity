package identity

import (
	"testing"
)

func TestNewID(t *testing.T) {
	id := NewID()
	if len(id) != 36 {
		t.Fatalf("expected id char length is 36, received %d", len(id))
	}
}
