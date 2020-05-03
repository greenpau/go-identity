package identity

import (
	"image"
)

// Image is base64 image
type Image struct {
	Title string `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	// Encoded Base64 string
	Body   string       `json:"body,omitempty" xml:"body,omitempty" yaml:"body,omitempty"`
	Config image.Config `json:"config,omitempty" xml:"config,omitempty" yaml:"config,omitempty"`
}

// NewImage returns an instance of Image.
func NewImage() *Image {
	return &Image{}
}
