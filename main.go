package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

const (
	cookieName        = "auth1"
	cookieMaxAge      = 7 * 24 * 60 * 60 // 7 days
	oauth2StateMaxAge = 10 * 60          // 10 minutes
)

type OAuth2State struct {
	RedirectURL string
}

type UserInfo struct {
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	User   string   `json:"user"`
	Groups []string `json:"groups"`
}

func httpError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

func getFromEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("missing required environment variable: %s", name)
	}
	if strings.HasPrefix(v, "file:/") {
		b, err := ioutil.ReadFile(v[5:])
		if err != nil {
			log.Fatal(err)
		}
		v = strings.TrimSpace(string(b))
	}
	return v
}

func getUserInfoFromGithub(ctx context.Context, client *http.Client, githubOrg string) (userInfo UserInfo, err error) {
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

func createAuthCookie(value string, maxAge int) http.Cookie {
	return http.Cookie{
		HttpOnly: true,
		MaxAge:   maxAge,
		Name:     cookieName,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Value:    value,
	}
}

func main() {
	cookieSerde := securecookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)
	cookieSerde.MaxAge(cookieMaxAge)

	stateSerde := securecookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)
	stateSerde.MaxAge(oauth2StateMaxAge)

	githubOrg := getFromEnv("GITHUB_ORG")
	oauth2ClientID := getFromEnv("GITHUB_OAUTH2_CLIENT_ID")
	oauth2ClientSecret := getFromEnv("GITHUB_OAUTH2_CLIENT_SECRET")
	oauth2CallbackURL := getFromEnv("GITHUB_OAUTH2_CALLBACK_URL")

	oauth2Config := oauth2.Config{
		ClientID:     oauth2ClientID,
		ClientSecret: oauth2ClientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  oauth2CallbackURL,
		Scopes:       []string{"user:email", "read:org"},
	}

	// example upstreams value: /api=http://localhost:9001,/some/path=http://host/other/path
	upstreams := getFromEnv("UPSTREAMS")
	proxies := http.NewServeMux()
	for _, upstream := range strings.Split(upstreams, ",") {
		parts := strings.SplitN(upstream, "=", 2)
		if len(parts) != 2 {
			log.Fatal("bad upstream: ", upstream)
		}
		pattern := parts[0]
		u, err := url.Parse(parts[1])
		if err != nil {
			log.Fatal(err)
		}
		if u.Scheme == "" || u.Host == "" {
			log.Fatal("bad upstream URL: ", u)
		}

		if !strings.HasPrefix(pattern, "/") {
			log.Fatal("bad pattern: ", pattern)
		}
		// for subtree matching to work, pattern has to end in '/'
		patternWithoutTrailingSlash := strings.TrimRight(pattern, "/")
		pattern = patternWithoutTrailingSlash + "/"

		log.Printf("routing %v -> %v", pattern, u)
		proxy := httputil.NewSingleHostReverseProxy(u)
		origDirector := proxy.Director
		proxy.Director = func(r *http.Request) {
			origURL := r.URL.String()
			r.URL.Path = strings.TrimPrefix(r.URL.Path, patternWithoutTrailingSlash)
			r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, patternWithoutTrailingSlash)
			origDirector(r)
			log.Printf("debug: redirected %s -> %s", origURL, r.URL.String())
		}
		proxies.Handle(pattern, proxy)
	}

	// handle OAuth2 authentication
	u, err := url.Parse(oauth2CallbackURL)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		stateString := r.URL.Query().Get("state")
		var state OAuth2State
		err = stateSerde.Decode("state", stateString, &state)
		if err != nil {
			log.Print(err)
			httpError(w, http.StatusBadRequest)
			return
		}
		log.Printf("got redirectURL %s", state.RedirectURL)
		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Print(err)
			httpError(w, http.StatusInternalServerError)
			return
		}

		client := oauth2Config.Client(ctx, oauth2Token)
		userInfo, err := getUserInfoFromGithub(ctx, client, githubOrg)
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
		cookieValue, err := cookieSerde.Encode(cookieName, userInfo)
		if err != nil {
			log.Print(err)
			httpError(w, http.StatusInternalServerError)
			return
		}
		cookie := createAuthCookie(cookieValue, cookieMaxAge)
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, state.RedirectURL, http.StatusFound)
	})

	http.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		// clear cookie
		cookie := createAuthCookie("", -1)
		http.SetCookie(w, &cookie)
		w.Write([]byte("logged out"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var userInfo UserInfo
		authenticated := false

		// check for cookie
		if cookie, err := r.Cookie(cookieName); err == nil {
			if err = cookieSerde.Decode(cookieName, cookie.Value, &userInfo); err == nil {
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
			state := OAuth2State{RedirectURL: r.RequestURI}
			stateString, err := stateSerde.Encode("state", state)
			if err != nil {
				log.Print(err)
				httpError(w, http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, oauth2Config.AuthCodeURL(stateString), http.StatusFound)
			return
		}

		// at this point we're authenticated

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

	listenAddress := ":" + os.Getenv("PORT")
	log.Printf("listening on %s", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
