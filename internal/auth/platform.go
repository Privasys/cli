// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Privasys/cli/internal/config"
)

// slotKey is where a platform's sign-in is stored: the issuer itself for the
// production platform (where every sign-in lived before there was one per
// platform), the issuer and the platform for any other.
func slotKey(issuer, platform string) string {
	if platform == "" || platform == PlatformAudience {
		return issuer
	}
	return issuer + "#" + platform
}

// isPlatformAudience reports an audience a platform's control plane accepts,
// whose tokens only that platform's own sign-in may give.
func isPlatformAudience(aud string) bool {
	return aud == config.DefaultAudience || aud == config.TestAudience || aud == CurrentPlatformAudience()
}

func platformName(aud string) string {
	switch aud {
	case "", config.DefaultAudience:
		return "the production platform (" + config.DefaultAudience + ")"
	case config.TestAudience:
		return "the test platform (" + config.TestAudience + ")"
	}
	return "the platform " + aud
}

// NotSignedInError says there is no sign-in for a platform. It matches
// ErrNotLoggedIn.
type NotSignedInError struct{ Platform string }

func (e *NotSignedInError) Error() string {
	return fmt.Sprintf("not signed in to %s: run `privasys auth login` with the same --endpoint or --test as this command", e.Platform)
}

// Is makes a NotSignedInError match ErrNotLoggedIn.
func (e *NotSignedInError) Is(target error) bool { return target == ErrNotLoggedIn }

// LoginScope is the scope a sign-in asks for on this run's platform: the
// production platform's is the default; another names its audience, so the
// sign-in is made for it.
func LoginScope() string {
	if aud := CurrentPlatformAudience(); aud != PlatformAudience {
		return DefaultScope + " audience:" + aud
	}
	return DefaultScope
}

// audienceOf is the platform audience a token was issued for, or "".
func audienceOf(token string) string {
	claims, err := Claims(token)
	if err != nil {
		return ""
	}
	switch a := claims["aud"].(type) {
	case string:
		if isPlatformAudience(a) {
			return a
		}
	case []interface{}:
		for _, x := range a {
			if s, _ := x.(string); isPlatformAudience(s) {
				return s
			}
		}
	}
	return ""
}

// lockWait and lockStale bound the credential lock: how long to wait for
// another privasys process, and when a lock is left over from one that died.
const (
	lockWait  = 30 * time.Second
	lockStale = 60 * time.Second
)

// withCredentialLock runs fn holding the cross-process credential lock. Every
// privasys process on the machine (each agent's MCP server, every CLI run)
// shares the stored sign-ins, and a refresh token is single-use: two that
// refresh at once would spend it twice and lose the sign-in. fn re-loads the
// credential under the lock, so a token another process just refreshed is
// used rather than refreshed again.
func withCredentialLock(fn func() error) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	lock := path + ".lock"
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
			_ = f.Close()
			defer os.Remove(lock)
			return fn()
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("lock the stored sign-ins: %w", err)
		}
		if fi, serr := os.Stat(lock); serr == nil && time.Since(fi.ModTime()) > lockStale {
			_ = os.Remove(lock) // left over from a process that died holding it
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("another privasys process has held the sign-in lock %s for %s; if none is running, delete that file", lock, lockWait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
