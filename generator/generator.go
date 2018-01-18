package generator

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	defaultScryptN   = 32768
	defaultScryptR   = 8
	defaultScryptP   = 1
	defaultScryptLen = 64
)

// Generator allow generate a new password
type Generator struct {
	scryptN   int
	scryptP   int
	scryptR   int
	scryptLen int
}

// NewByDefault : _
func NewByDefault() Generator {
	return Generator{
		scryptN:   defaultScryptN,
		scryptP:   defaultScryptP,
		scryptR:   defaultScryptR,
		scryptLen: defaultScryptLen,
	}
}

// New : _
func New(SN, SP, SR, SLen int) Generator {
	return Generator{
		scryptN:   SN,
		scryptP:   SP,
		scryptR:   SR,
		scryptLen: SLen,
	}
}

// CreateNewPassword generate encrypted password and return it with the random salt and error status
func (g Generator) CreateNewPassword(pass string) ([]byte, []byte, error) {
	var err error
	var password []byte
	salt := make([]byte, 32)

	// get salt
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}

	// get password encrypted
	password, err = scrypt.Key([]byte(pass), salt, g.scryptN, g.scryptR, g.scryptP, g.scryptLen)
	if err != nil {
		return nil, nil, err
	}
	return password, salt, nil
}

// GetEncryptedPassword return the encrypted password with the salt specified on parameter
func (g Generator) GetEncryptedPassword(pass string, salt []byte) ([]byte, error) {
	password, err := scrypt.Key([]byte(pass), salt, g.scryptN, g.scryptR, g.scryptP, g.scryptLen)
	return password, err
}
