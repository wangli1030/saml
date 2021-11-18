package samlsp

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wangli1030/saml"
)

const defaultSessionCookieName = "token"
const cookieMaxLength = 3000

var _ SessionProvider = CookieSessionProvider{}

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Codec    SessionCodec
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	session, err := c.Codec.New(assertion)
	if err != nil {
		return err
	}

	value, err := c.Codec.Encode(session)
	if err != nil {
		return err
	}
	var cookieList []string
	for i := 0; i < len(value); i = i + cookieMaxLength {
		end := i + cookieMaxLength
		if end > len(value) {
			end = len(value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     c.Name + strconv.Itoa(i),
			Domain:   c.Domain,
			Value:    value[i:end],
			MaxAge:   int(c.MaxAge.Seconds()),
			HttpOnly: c.HTTPOnly,
			Secure:   c.Secure || r.URL.Scheme == "https",
			SameSite: c.SameSite,
			Path:     "/",
		})
		cookieList = append(cookieList, c.Name+strconv.Itoa(i))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    strings.Join(cookieList, ","),
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
		SameSite: c.SameSite,
		Path:     "/",
	})
	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c CookieSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	cookie, err := r.Cookie(c.Name)

	if err == http.ErrNoCookie {
		return nil
	}
	if err != nil {
		return err
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	cookie.Path = "/"
	cookie.Domain = c.Domain
	http.SetCookie(w, cookie)
	return nil
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (c CookieSessionProvider) GetSession(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(c.Name)
	if err == http.ErrNoCookie {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}
	cookieList := strings.Split(cookie.Value, ",")
	var sessionValue string
	for _, s := range cookieList {
		cookie, err := r.Cookie(s)
		if err == http.ErrNoCookie {
			return nil, ErrNoSession
		} else if err != nil {
			return nil, err
		}
		sessionValue = sessionValue + cookie.Value
	}

	session, err := c.Codec.Decode(sessionValue)
	if err != nil {
		return nil, ErrNoSession
	}
	return session, nil
}
