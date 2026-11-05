package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// writePEM writes a DER blob as a PEM file with the given permissions, creating it
// atomically so a crash cannot leave a half-written key behind.
func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// sha256Hex renders a certificate fingerprint the way browsers display it.
func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	hexStr := hex.EncodeToString(sum[:])
	var b strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(hexStr[i : i+2]))
	}
	return b.String()
}
