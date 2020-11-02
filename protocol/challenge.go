package protocol

import (
	"crypto/rand"
	"encoding/base64"
)

// ChallengeLength - Length of bytes to generate for a challenge
const ChallengeLength = 32

// Challenge that should be signed and returned by the authenticator
type Challenge URLEncodedBase64

// Create a new challenge to be sent to the authenticator. The spec recommends using
// at least 16 bytes with 100 bits of entropy. We use 32 bytes.
func CreateChallenge(payload string) (Challenge, error) {
	payloadInBytes := []byte(payload)
	tmp := make([]byte, ChallengeLength)
	_, err := rand.Read(tmp)
	if err != nil {
		return nil, err
	}
	challenge := append(payloadInBytes, tmp...)
	return challenge, nil
}

func (c Challenge) String() string {
	return base64.RawURLEncoding.EncodeToString(c)
}
