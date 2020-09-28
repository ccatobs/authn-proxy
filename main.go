package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	cookieName         = "auth1"
	cookieMaxAge       = 7 * 24 * 60 * 60 // 7 days
	githubOrg          = "ccatp"
	listenAddress      = "127.0.0.1:" + os.Getenv("PORT")
	oauth2ClientID     = os.Getenv("GITHUB_OAUTH2_CLIENT_ID")
	oauth2ClientSecret = os.Getenv("GITHUB_OAUTH2_CLIENT_SECRET")
	oauth2CallbackURL  = os.Getenv("GITHUB_OAUTH2_CALLBACK_URL")
	upstreamURL        = os.Getenv("UPSTREAM_URL")
)

type UserInfo struct {
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	User   string   `json:"user"`
	Groups []string `json:"groups"`
}

func httpError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

func getUserInfoFromGithub(ctx context.Context, client *http.Client) (userInfo UserInfo, err error) {
	query := `{"query": "query{viewer{name,login,email,organization(login:\"` + githubOrg + `\"){teams(first:100){nodes{slug}}}}}"}`
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.github.com/graphql", bytes.NewBufferString(query))
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			Viewer struct {
				Email string `json:"email"`
				Login string `json:"login"`
				Name  string `json:"name"`
				Org   struct {
					Teams struct {
						Nodes []struct {
							Slug string `json:"slug"`
						} `json:"nodes"`
					} `json:"teams"`
				} `json:"organization"`
			} `json:"viewer"`
		} `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	log.Printf("%+v", result)
	userInfo.Email = result.Data.Viewer.Email
	userInfo.Name = result.Data.Viewer.Name
	userInfo.User = result.Data.Viewer.Login
	for _, node := range result.Data.Viewer.Org.Teams.Nodes {
		userInfo.Groups = append(userInfo.Groups, node.Slug)
	}
	return
}

// https://tools.ietf.org/html/rfc2253, section 3
func parseCertSubject(subject string) (map[string][]string, error) {
	// split on ',' or '+', and unescape '\' sequences
	var parts []string
	part := ""
	escape := false
	ignore := 0
	for i, rune := range subject {
		if ignore > 0 {
			ignore = ignore - 1
		} else if escape {
			escape = false
			switch rune {
			case ',', '=', '+', '<', '>', '#', ';', '"', '\\':
				part = part + string(rune)
			default:
				bs, err := hex.DecodeString(subject[i : i+2])
				if err != nil {
					return nil, err
				}
				part = part + string(bs)
				ignore = 1
			}
		} else {
			switch rune {
			case '\\':
				escape = true
			case ',', '+':
				parts = append(parts, part)
				part = ""
			default:
				part = part + string(rune)
			}
		}
	}
	if escape || ignore != 0 {
		return nil, fmt.Errorf("bad distinguishedName: %s", subject)
	}
	parts = append(parts, part)

	kvs := make(map[string][]string)
	for _, kv := range parts {
		i := strings.IndexRune(kv, '=')
		if i < 1 {
			return nil, fmt.Errorf("bad attributeTypeAndValue: %s", kv)
		}
		k, v := kv[:i], kv[i+1:]
		if v[0] == '#' {
			bs, err := hex.DecodeString(v[1:])
			if err != nil {
				return nil, err
			}
			v = string(bs)
		}
		kvs[k] = append(kvs[k], v)
	}
	return kvs, nil
}

func userInfoFromCertSubject(subject string, userInfo *UserInfo) error {
	m, err := parseCertSubject(subject)
	if err != nil {
		return err
	}
	if v, ok := m["CN"]; ok {
		userInfo.Name = v[0]
	}
	if v, ok := m["emailAddress"]; ok {
		userInfo.Email = v[0]
	}
	if v, ok := m["UID"]; ok {
		userInfo.User = v[0]
	}
	if v, ok := m["OU"]; ok {
		userInfo.Groups = v
	}
	return nil
}

func main() {
	secure := securecookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)
	secure.MaxAge(cookieMaxAge)

	oauth2Config := oauth2.Config{
		ClientID:     oauth2ClientID,
		ClientSecret: oauth2ClientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  oauth2CallbackURL,
		Scopes:       []string{"user:email", "read:org"},
	}

	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Director = func(r *http.Request) {
		r.URL.Host = upstream.Host
		r.URL.Scheme = upstream.Scheme
	}
	proxies := http.NewServeMux()
	proxies.Handle("/", proxy)

	// handle OAuth2 authentication
	u, err := url.Parse(oauth2CallbackURL)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		state := r.URL.Query().Get("state")
		log.Printf("got state: %s", state)
		var redirectURL string
		err = secure.Decode("redirectURL", state, &redirectURL)
		if err != nil {
			log.Print(err)
			httpError(w, http.StatusBadRequest)
			return
		}
		log.Printf("got redirectURL %s", redirectURL)
		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Print(err)
			httpError(w, http.StatusInternalServerError)
			return
		}
		log.Printf("%+v", oauth2Token)

		client := oauth2Config.Client(ctx, oauth2Token)
		userInfo, err := getUserInfoFromGithub(ctx, client)
		if err != nil {
			log.Print(err)
			httpError(w, http.StatusInternalServerError)
			return
		}

		if len(userInfo.Groups) == 0 {
			log.Print("not a member of any groups")
			httpError(w, http.StatusUnauthorized)
			return
		}

		log.Printf("userInfo = %+v", userInfo)
		encoded, err := secure.Encode(cookieName, userInfo)
		if err != nil {
			log.Print(err)
			httpError(w, http.StatusInternalServerError)
			return
		}
		cookie := &http.Cookie{
			HttpOnly: true,
			MaxAge:   cookieMaxAge,
			Name:     cookieName,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			Value:    encoded,
		}
		log.Printf("cookie = %+v", cookie)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var userInfo UserInfo
		authenticated := false

		// check for cookie
		if cookie, err := r.Cookie(cookieName); err == nil {
			if err = secure.Decode(cookieName, cookie.Value, &userInfo); err == nil {
				log.Print("authenticated by cookie")
				authenticated = true
			}
		}

		// check for TLS client certificate
		tlsClientSubject := r.Header.Get("X-Tls-Client-Subject")
		if tlsClientSubject != "" {
			log.Print("tlsClientSubject: ", tlsClientSubject)
			if err := userInfoFromCertSubject(tlsClientSubject, &userInfo); err == nil {
				log.Print("authenticated by client certificate")
				authenticated = true
			}
		}

		if !authenticated {
			log.Printf("not logged in")
			state, err := secure.Encode("redirectURL", r.RequestURI)
			if err != nil {
				log.Print(err)
				httpError(w, http.StatusInternalServerError)
				return
			}
			log.Printf("sent oauth2 state: %s", state)
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		if r.URL.Path == "/auth/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(&userInfo)
			if err != nil {
				log.Print(err)
			}
			return
		}

		log.Printf("userInfo: %+v", userInfo)
		r.Header.Set("X-Auth-Name", userInfo.Name)
		r.Header.Set("X-Auth-Email", userInfo.Email)
		r.Header.Set("X-Auth-User", userInfo.User)
		r.Header.Set("X-Auth-Groups", strings.Join(userInfo.Groups, ","))
		proxies.ServeHTTP(w, r)
	})

	log.Printf("listening on %s", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
