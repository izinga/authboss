package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/izinga/authboss"
	"github.com/izinga/authboss/internal/response"
	"golang.org/x/oauth2"
)

var (
	errOAuthStateValidation = errors.New("Could not validate oauth2 state param")
	RedirectURL             = ""
)

// OAuth2 module
type OAuth2 struct {
	*authboss.Authboss
}

func init() {
	authboss.RegisterModule("oauth2", &OAuth2{})
}

// Initialize module
func (o *OAuth2) Initialize(ab *authboss.Authboss) error {
	o.Authboss = ab
	if o.OAuth2Storer == nil && o.OAuth2StoreMaker == nil {
		return errors.New("oauth2: need an OAuth2Storer")
	}
	return nil
}

// Routes for module
func (o *OAuth2) Routes() authboss.RouteTable {
	routes := make(authboss.RouteTable)

	for prov, cfg := range o.OAuth2Providers {
		prov = strings.ToLower(prov)

		init := fmt.Sprintf("/oauth2/%s", prov)
		callback := fmt.Sprintf("/oauth2/callback/%s", prov)

		routes[init] = o.oauthInit
		routes[callback] = o.oauthCallback

		if len(o.MountPath) > 0 {
			callback = path.Join(o.MountPath, callback)
		}
		RedirectURL = callback
		cfg.OAuth2Config.RedirectURL = callback
	}
	routes["/oauth2/logout"] = o.logout

	return routes
}

// getRootUrl get root url
func (o *OAuth2) getRootUrl() string {
	return o.RootURL
}

// Storage requirements
func (o *OAuth2) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		authboss.StoreEmail:          authboss.String,
		authboss.StoreOAuth2UID:      authboss.String,
		authboss.StoreOAuth2Provider: authboss.String,
		authboss.StoreOAuth2Token:    authboss.String,
		authboss.StoreOAuth2Refresh:  authboss.String,
		authboss.StoreOAuth2Expiry:   authboss.DateTime,
	}
}

func (o *OAuth2) oauthInit(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {

	protocal := os.Getenv("ROBUSTEST_GOOGLE_AUTH_PROTOCOL")
	if protocal == "" {
		protocal = "https"
	}

	o.RootURL = protocal + "://" + r.Host
	provider := strings.ToLower(filepath.Base(r.URL.Path))
	cfg, ok := o.OAuth2Providers[provider]
	if !strings.Contains(cfg.OAuth2Config.RedirectURL, o.RootURL) {
		fmt.Println("We are geneating redirect url", o.RootURL, RedirectURL, cfg.OAuth2Config.RedirectURL)
		cfg.OAuth2Config.RedirectURL = o.RootURL + RedirectURL
	}

	if !ok {
		return fmt.Errorf("OAuth2 provider %q not found", provider)
	}

	random := make([]byte, 32)
	_, err := rand.Read(random)
	if err != nil {
		return err
	}

	state := base64.URLEncoding.EncodeToString(random)
	ctx.SessionStorer.Put(authboss.SessionOAuth2State, state)

	passAlongs := make(map[string]string)
	for k, vals := range r.URL.Query() {
		for _, val := range vals {
			passAlongs[k] = val
		}
	}

	if len(passAlongs) > 0 {
		str, err := json.Marshal(passAlongs)
		if err != nil {
			return err
		}
		ctx.SessionStorer.Put(authboss.SessionOAuth2Params, string(str))
	} else {
		ctx.SessionStorer.Del(authboss.SessionOAuth2Params)
	}

	url := cfg.OAuth2Config.AuthCodeURL(state)

	extraParams := cfg.AdditionalParams.Encode()
	if len(extraParams) > 0 {
		url = fmt.Sprintf("%s&%s", url, extraParams)
	}

	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

// for testing
var exchanger = (*oauth2.Config).Exchange

func (o *OAuth2) oauthCallback(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {

	fmt.Println("oauthCallback url ", r.URL.String())
	provider := strings.ToLower(filepath.Base(r.URL.Path))
	if strings.Contains(provider, "microsoft") {
		fmt.Println("We got microsoft we need to use different code")
	}
	var err error
	// sessState, err := ctx.SessionStorer.GetErr(authboss.SessionOAuth2State)
	ctx.SessionStorer.Del(authboss.SessionOAuth2State)
	if err != nil {
		fmt.Println("oauthCallback SessionStorer delete error  ", err)
		// return err
	}

	sessValues, ok := ctx.SessionStorer.Get(authboss.SessionOAuth2Params)
	// Don't delete this value from session immediately, callbacks use this too
	var values map[string]string
	if ok {
		if err := json.Unmarshal([]byte(sessValues), &values); err != nil {
			fmt.Println("oauthCallback Unmarshal  ", err)
			// return err
		}
	}

	hasErr := r.FormValue("error")
	if len(hasErr) > 0 {
		fmt.Println("oauthCallback Unmarshal hasErr  ")
		if err := o.Callbacks.FireAfter(authboss.EventOAuthFail, ctx); err != nil {
			// return err
		}

		// return authboss.ErrAndRedirect{
		// 	Err:        errors.New(r.FormValue("error_reason")),
		// 	Location:   o.AuthLoginFailPath,
		// 	FlashError: fmt.Sprintf("%s login cancelled or failed.", strings.Title(provider)),
		// }
	}

	cfg, ok := o.OAuth2Providers[provider]
	if !ok {
		fmt.Println("oauthCallback Unmarshal OAuth2Providers  ", fmt.Errorf("OAuth2 provider %q not found", provider))
		return fmt.Errorf("OAuth2 provider %q not found", provider)
	}

	// Ensure request is genuine
	// state := r.FormValue(authboss.FormValueOAuth2State)
	// splState := strings.Split(state, ";")
	// if len(splState) == 0 || splState[0] != sessState {
	// 	fmt.Println("oauthCallback Unmarshal errOAuthStateValidation  ", errOAuthStateValidation)
	// 	return errOAuthStateValidation
	// }

	// Get the code
	code := r.FormValue("code")
	token := &oauth2.Token{}
	if strings.Contains(provider, "microsoft") {
		fmt.Println("We got microsoft we need to use different code", code)
		ctx := context.Background()
		if token, err = cfg.OAuth2Config.Exchange(ctx, code); err != nil {
			fmt.Println("Failed to get microsoft token, Error - ", err)
			return err
		} else {
			fmt.Printf("\ngot microsoft token %+v\n", token)
		}

	} else {
		token, err = exchanger(cfg.OAuth2Config, o.Config.ContextProvider(r), code)
		if err != nil {
			fmt.Println("oauthCallback Unmarshal errOAuthStateValidation  ", fmt.Errorf("Could not validate oauth2 code: %v", err))
			return fmt.Errorf("Could not validate oauth2 code: %v", err)
		}
	}
	user, err := cfg.Callback(o.Config.ContextProvider(r), *cfg.OAuth2Config, token)
	if err != nil {
		fmt.Println("oauthCallback Unmarshal Callback  ", err)
		return err
	}

	// OAuth2UID is required.
	uid, err := user.StringErr(authboss.StoreOAuth2UID)
	fmt.Println("oauthCallback Unmarshal StringErr  ", err)
	// if err != nil {
	// 	return err
	// }

	user[authboss.StoreOAuth2UID] = uid
	user[authboss.StoreOAuth2Provider] = provider
	user[authboss.StoreOAuth2Expiry] = token.Expiry
	user[authboss.StoreOAuth2Token] = token.AccessToken
	if len(token.RefreshToken) != 0 {
		user[authboss.StoreOAuth2Refresh] = token.RefreshToken
	}

	if err = ctx.OAuth2Storer.PutOAuth(uid, provider, user); err != nil {
		fmt.Println("oauthCallback We got error here ", err)

		sf := "Sign in Failed. Try signing in with email address of an authorised domain."
		response.Redirect(ctx, w, r, o.AuthLoginOKPath, sf, "", false)
		return nil
	}

	// Fully log user in
	ctx.SessionStorer.Put(authboss.SessionKey, fmt.Sprintf("%s;%s", uid, provider))
	ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)

	if err = o.Callbacks.FireAfter(authboss.EventOAuth, ctx); err != nil {
		fmt.Println("oauthCallback We got error FireAfter ", err)
		// return nil
	}

	ctx.SessionStorer.Del(authboss.SessionOAuth2Params)

	redirect := o.AuthLoginOKPath
	query := make(url.Values)
	for k, v := range values {
		switch k {
		case authboss.CookieRemember:
		case authboss.FormValueRedirect:
			redirect = v
		default:
			query.Set(k, v)
		}
	}

	if len(query) > 0 {
		redirect = fmt.Sprintf("%s?%s", redirect, query.Encode())
	}
	fmt.Println(fmt.Sprintf(" oauthCallback Logged in successfully with %s.", strings.Title(provider)))
	fmt.Println("oauthCallback We are redirecting to ", redirect)
	sf := fmt.Sprintf("oauthCallback Logged in successfully with %s.", strings.Title(provider))
	response.Redirect(ctx, w, r, redirect, sf, "", false)
	return nil
}

func (o *OAuth2) logout(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		ctx.SessionStorer.Del(authboss.SessionKey)
		ctx.CookieStorer.Del(authboss.CookieRemember)
		ctx.SessionStorer.Del(authboss.SessionLastAction)

		response.Redirect(ctx, w, r, o.AuthLogoutOKPath, "You have logged out", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
