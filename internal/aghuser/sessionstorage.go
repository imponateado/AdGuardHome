package aghuser

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/google/renameio/v2/maybe"
)

// SessionStorage is an interface that defines methods for handling web user
// sessions.  All methods must be safe for concurrent use.
//
// TODO(s.chzhen):  Add DeleteAll method.
type SessionStorage interface {
	// New creates a new session for the web user.
	New(ctx context.Context, u *User) (s *Session, err error)

	// FindByToken returns the stored session for the web user based on the session
	// token.
	//
	// TODO(s.chzhen):  Consider function signature change to reflect the
	// in-memory implementation, as it currently always returns nil for error.
	FindByToken(ctx context.Context, t SessionToken) (s *Session, err error)

	// DeleteByToken removes a stored web user session by the provided token.
	DeleteByToken(ctx context.Context, t SessionToken) (err error)

	// Close releases the web user sessions database resources.
	Close() (err error)
}

// DefaultSessionStorageConfig represents the web user session storage
// configuration structure.
type DefaultSessionStorageConfig struct {
	// Logger is used for logging the operation of the session storage.  It must
	// not be nil.
	Logger *slog.Logger

	// Clock is used to get the current time.  It must not be nil.
	Clock timeutil.Clock

	// UserDB contains the web user information such as ID, login, and password.
	// It must not be nil.
	UserDB DB

	// DBPath is the path to the JSON file where session data is stored.  It
	// must not be empty.
	DBPath string

	// SessionTTL is the default Time-To-Live duration for web user sessions.
	// It specifies how long a session should last and is a required field.
	SessionTTL time.Duration
}

// DefaultSessionStorage is the default JSON file implementation of the
// [SessionStorage] interface.  Sessions are kept in memory and the whole set is
// rewritten atomically to the file on every change.
type DefaultSessionStorage struct {
	// logger is used for logging the operation of the session storage.
	logger *slog.Logger

	// mu protects sessions and the file.
	mu *sync.Mutex

	// clock is used to get the current time.
	clock timeutil.Clock

	// userDB contains the web user information such as ID, login, and password.
	userDB DB

	// sessions maps a session token to a web user session.
	sessions map[SessionToken]*Session

	// path is the path to the JSON file with the sessions.
	path string

	// sessionTTL is the default Time-To-Live value for web user sessions.
	sessionTTL time.Duration
}

// storedSession is the JSON representation of a session in the file.  The
// token is the key of the map in the file.
type storedSession struct {
	// Login is the login of the web user.
	Login Login `json:"login"`

	// Expire is the session expiration time as Unix seconds.
	Expire int64 `json:"expire"`
}

// NewDefaultSessionStorage returns the new properly initialized
// *DefaultSessionStorage.
func NewDefaultSessionStorage(
	ctx context.Context,
	conf *DefaultSessionStorageConfig,
) (ds *DefaultSessionStorage, err error) {
	ds = &DefaultSessionStorage{
		clock:      conf.Clock,
		userDB:     conf.UserDB,
		logger:     conf.Logger,
		mu:         &sync.Mutex{},
		sessions:   map[SessionToken]*Session{},
		path:       conf.DBPath,
		sessionTTL: conf.SessionTTL,
	}

	err = ds.loadSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading sessions: %w", err)
	}

	return ds, nil
}

// loadSessions loads web user sessions from the file and removes the invalid
// ones from it.  A missing, empty, or malformed file means no sessions.
func (ds *DefaultSessionStorage) loadSessions(ctx context.Context) (err error) {
	data, err := os.ReadFile(ds.path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
		return nil
	} else if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	stored := map[string]storedSession{}
	err = json.Unmarshal(data, &stored)
	if err != nil {
		// Sessions are disposable, so users just log in again.
		ds.logger.ErrorContext(ctx, "decoding sessions file", slogutil.KeyError, err)
	}

	now := ds.clock.Now()
	for k, v := range stored {
		s := ds.restoreSession(ctx, now, k, v)
		if s != nil {
			ds.sessions[s.Token] = s
		}
	}

	removed := len(stored) - len(ds.sessions)
	ds.logger.DebugContext(ctx, "loading sessions", "stored", len(ds.sessions), "removed", removed)

	if removed == 0 && err == nil {
		return nil
	}

	return ds.save()
}

// restoreSession returns the session stored under the hex-encoded token k, or
// nil if the token is malformed, the session has expired, or its user no longer
// exists.
func (ds *DefaultSessionStorage) restoreSession(
	ctx context.Context,
	now time.Time,
	k string,
	v storedSession,
) (s *Session) {
	var t SessionToken
	if n, err := hex.Decode(t[:], []byte(k)); err != nil || n != SessionTokenLength {
		return nil
	}

	s = &Session{Token: t, UserLogin: v.Login, Expire: time.Unix(v.Expire, 0)}
	if now.After(s.Expire) {
		return nil
	}

	u, err := ds.userDB.ByLogin(ctx, s.UserLogin)
	if err != nil {
		// Should not happen, as it currently always returns nil for error.
		panic(err)
	}

	if u == nil {
		ds.logger.DebugContext(ctx, "no saved user by name", "name", s.UserLogin)

		return nil
	}

	s.UserID = u.ID

	return s
}

// save atomically writes all sessions to the file.  ds.mu is expected to be
// locked, except during construction.
func (ds *DefaultSessionStorage) save() (err error) {
	stored := make(map[string]storedSession, len(ds.sessions))
	for t, s := range ds.sessions {
		stored[hex.EncodeToString(t[:])] = storedSession{Login: s.UserLogin, Expire: s.Expire.Unix()}
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("encoding sessions: %w", err)
	}

	// Tokens grant access, so keep the file private.
	err = maybe.WriteFile(ds.path, data, aghos.DefaultPermFile)
	if err != nil {
		return fmt.Errorf("writing sessions file: %w", err)
	}

	return nil
}

// type check
var _ SessionStorage = (*DefaultSessionStorage)(nil)

// New implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) New(ctx context.Context, u *User) (s *Session, err error) {
	s = &Session{
		Token:     NewSessionToken(),
		UserID:    u.ID,
		UserLogin: u.Login,
		Expire:    ds.clock.Now().Add(ds.sessionTTL),
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.sessions[s.Token] = s

	err = ds.save()
	if err != nil {
		delete(ds.sessions, s.Token)

		return nil, fmt.Errorf("storing session: %w", err)
	}

	return s, nil
}

// FindByToken implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) FindByToken(ctx context.Context, t SessionToken) (s *Session, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	s, ok := ds.sessions[t]
	if !ok {
		return nil, nil
	}

	now := ds.clock.Now()
	if now.After(s.Expire) {
		err = ds.deleteByToken(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("expired session: %w", err)
		}

		return nil, nil
	}

	return s, nil
}

// DeleteByToken implements the [SessionStorage] interface for
// *DefaultSessionStorage.
func (ds *DefaultSessionStorage) DeleteByToken(ctx context.Context, t SessionToken) (err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Don't wrap the error because it's informative enough as is.
	return ds.deleteByToken(ctx, t)
}

// deleteByToken removes stored session by token.  ds.mu is expected to be
// locked.
func (ds *DefaultSessionStorage) deleteByToken(ctx context.Context, t SessionToken) (err error) {
	s, ok := ds.sessions[t]
	delete(ds.sessions, t)

	err = ds.save()
	if err != nil {
		if ok {
			ds.sessions[t] = s
		}

		ds.logger.ErrorContext(ctx, "deleting session", slogutil.KeyError, err)

		return err
	}

	ds.logger.DebugContext(ctx, "removed session from file")

	return nil
}

// Close implements the [SessionStorage] interface for *DefaultSessionStorage.
// Every change is already written, so there is nothing to release.
func (ds *DefaultSessionStorage) Close() (err error) {
	return nil
}
