package ensweb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/EnsurityTechnologies/enscrypt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func (s *Server) getSharedSecret(req *Request) error {
	if req.nss != nil {
		return nil
	}
	if req.ss != "" {
		return nil
	}
	pubkey := s.GetReqHeader(req, PublicKeyHdr)
	pb, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		s.log.Error("invalid pubkey, failed to decode base 64 string", "err", err)
		return err
	}

	tot := make([]byte, len(pb)+1)
	tot[0] = 0x04
	copy(tot[1:], pb)
	pk, err := secp256k1.ParsePubKey(tot)
	if err == nil {
		req.nss = secp256k1.GenerateSharedSecret(s.npk, pk)
		return nil
	}

	pub, err := ecdh.P256().NewPublicKey(pb)
	if err != nil {
		s.log.Error("invalid pubkey, failed to frame pubkey", "err", err)
		return err
	}
	kb, err := s.pk.ECDH(pub)
	if err != nil {
		s.log.Error("failed to create shared secret", "err", err)
		return err
	}
	ss := sha256.Sum256(kb)
	req.ss = hex.EncodeToString(ss[:])
	return nil
}

func encryptModel(nss []byte, ss string, model interface{}) (string, error) {
	data, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	if nss != nil {
		aes, err := aes.NewCipher(nss)
		if err != nil {
			return "", err
		}
		//block cipher wrapped in Galois Counter Mode
		gcm, err := cipher.NewGCMWithNonceSize(aes, 16)
		if err != nil {
			return "", err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return "", err
		}
		cipherText := gcm.Seal(nil, nonce, data, nil)
		return packCipherData(cipherText, nonce, gcm.Overhead()), nil
	}
	eb, err := enscrypt.Seal(ss, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(eb), nil
}

func decryptModel(nss []byte, ss string, data string, model interface{}) error {
	eb, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	if nss != nil {
		aes, err := aes.NewCipher(nss)
		if err != nil {
			return err
		}
		//block cipher wrapped in Galois Counter Mode
		aesgcm, err := cipher.NewGCMWithNonceSize(aes, 16)
		if err != nil {
			return err
		}
		encryptedBytes, nonce := unpackCipherData(eb, aesgcm.NonceSize())
		db, err := aesgcm.Open(nil, nonce, encryptedBytes, nil)
		if err != nil {
			return err
		}
		err = json.Unmarshal(db, model)
		if err != nil {
			return err
		}
		return nil
	}
	db, err := enscrypt.UnSeal(ss, eb)
	if err != nil {
		return err
	}
	err = json.Unmarshal(db, model)
	if err != nil {
		return err
	}
	return nil
}

// private functions
func packCipherData(cipherText []byte, iv []byte, tagSize int) string {
	ivLen := len(iv)
	data := make([]byte, len(cipherText)+ivLen)
	copy(data[:], iv[0:ivLen])
	copy(data[ivLen:], cipherText)
	return base64.StdEncoding.EncodeToString(data)
}

func unpackCipherData(data []byte, ivSize int) ([]byte, []byte) {
	iv, encryptedBytes := data[:ivSize], data[ivSize:]
	return encryptedBytes, iv
}
