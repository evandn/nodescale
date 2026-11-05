package gate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// nonceStore gives replay protection without a long-running process: every
// accepted request atomically creates a file named after its nonce. A second
// attempt with the same nonce fails with EEXIST. Files are pruned once the
// requests they guard could no longer pass the expiry check.
type nonceStore struct {
	dir    string
	maxAge time.Duration
}

func (n nonceStore) use(signer, nonce string, now time.Time) (bool, error) {
	if err := os.MkdirAll(n.dir, 0o770); err != nil {
		return false, err
	}
	h := sha256.Sum256([]byte(signer + "\x00" + nonce))
	path := filepath.Join(n.dir, hex.EncodeToString(h[:16]))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o660)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, _ = f.WriteString(strconv.FormatInt(now.Unix(), 10))
	f.Close()
	n.maybePrune(now)
	return true, nil
}

// maybePrune removes expired nonce files on roughly one call in 32, which
// keeps the directory small without a background job.
func (n nonceStore) maybePrune(now time.Time) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil || b[0]&31 != 0 {
		return
	}
	n.prune(now)
}

func (n nonceStore) prune(now time.Time) {
	entries, err := os.ReadDir(n.dir)
	if err != nil {
		return
	}
	cutoff := now.Add(-n.maxAge)
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(n.dir, e.Name()))
		}
	}
}
