package identity

import (
	"testing"
)

func TestNewID(t *testing.T) {
	id := NewID()
	if len(id) != 32 {
		t.Fatalf("expected id char length is 32, received %d", len(id))
	}
}
