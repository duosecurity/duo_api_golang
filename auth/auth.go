package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/duosecurity/duo_api_golang"
)

// Client provides access to Duo's auth API.
type Client struct {
	duoapi.BaseClient
}

// New initializes and returns a Client for the Duo Auth API.
// The base parameter is a duoapi.BaseClient, and is used to make signed calls to the Duo API.
// Example: auth.New(*duoapi.New(ikey, skey, host, userAgent, duoapi.SetTimeout(10*time.Second)))
func New(base duoapi.BaseClient) *Client {
	return &Client{base}
}

// TimeResult models responses containing a time value.
type TimeResult struct {
	duoapi.BaseResult
	Response struct {
		Time int64
	}
}

// Ping calls GET /auth/v2/ping
// See https://duo.com/docs/authapi#/ping
// This is an unsigned Duo Rest API call which returns the Duo system's time.
// Use this method to determine whether your system time is in sync with Duo's.
func (c *Client) Ping() (*TimeResult, error) {
	_, body, err := c.Call(http.MethodGet, "/auth/v2/ping", nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}
	ret := &TimeResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// Check calls GET /auth/v2/check
// See https://duo.com/docs/authapi#/check
// Check is a signed Duo API call, which returns the Duo system's time.
// Use this method to determine whether your ikey, skey and host are correct,
// and whether your system time is in sync with Duo's.
func (c *Client) Check() (*TimeResult, error) {
	_, body, err := c.SignedCall(http.MethodGet, "/auth/v2/check", nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}
	ret := &TimeResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// LogoResult models responses containing raw PNG image data.
type LogoResult struct {
	duoapi.BaseResult
	PNG *[]byte
}

// Logo calls GET /auth/v2/logo
// See https://duo.com/docs/authapi#/logo
// If the API call is successful, the configured logo png is returned. Othwerwise,
// error information is returned in the LogoResult return value.
func (c *Client) Logo() (*LogoResult, error) {
	resp, body, err := c.SignedCall(http.MethodGet, "/auth/v2/logo", nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 200 {
		ret := &LogoResult{BaseResult: duoapi.BaseResult{Stat: "OK"}, PNG: &body}
		return ret, nil
	}
	ret := &LogoResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// EnrollUsername sets the optional username parameter for an Enroll request.
func EnrollUsername(username string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("username", username)
	}
}

// EnrollValidSeconds sets the optional valid_secs parameter for an Enroll request.
func EnrollValidSeconds(secs uint64) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("valid_secs", strconv.FormatUint(secs, 10))
	}
}

// EnrollResult models responses containing 2FA enrollment data information.
type EnrollResult struct {
	duoapi.BaseResult
	Response struct {
		ActivationBarcode string `json:"activation_barcode"`
		ActivationCode    string `json:"activation_code"`
		Expiration        int64
		UserID            string `json:"user_id"`
		Username          string
	}
}

// Enroll calls POST /auth/v2/enroll
// See https://duo.com/docs/authapi#/enroll
// Use EnrollUsername() to set the optional username parameter.
// Use EnrollValidSeconds() to change the default validation time limit that the
// user has to complete enrollment.
func (c *Client) Enroll(options ...func(*url.Values)) (*EnrollResult, error) {
	opts := url.Values{}
	for _, o := range options {
		o(&opts)
	}

	_, body, err := c.SignedCall(http.MethodPost, "/auth/v2/enroll", opts, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}
	ret := &EnrollResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// EnrollStatus calls POST /auth/v2/enroll_status
// See https://duo.com/docs/authapi#/enroll_status
// Return the status of an outstanding Enrollment.
// Response is one of {"success", "invalid", "waiting"}
func (c *Client) EnrollStatus(userid string, activationCode string) (*duoapi.StringResult, error) {
	queryArgs := url.Values{}
	queryArgs.Set("user_id", userid)
	queryArgs.Set("activation_code", activationCode)

	_, body, err := c.SignedCall(http.MethodPost, "/auth/v2/enroll_status", queryArgs, duoapi.UseTimeout)

	if err != nil {
		return nil, err
	}
	ret := &duoapi.StringResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// PreauthResult models responses containing available authentication factors.
type PreauthResult struct {
	duoapi.BaseResult
	Response struct {
		Result          string
		StatusMsg       string `json:"status_msg"`
		EnrollPortalURL string `json:"enroll_portal_url"`
		Devices         []struct {
			Device       string
			Type         string
			Name         string
			Number       string
			Capabilities []string
		}
	}
}

// PreauthUserID sets the user_id parameter for a Preauth request.
func PreauthUserID(userID string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("user_id", userID)
	}
}

// PreauthUsername sets the username parameter for a Preauth request.
func PreauthUsername(username string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("username", username)
	}
}

// PreauthIPAddr sets the optional ipaddr parameter for a Preauth request.
func PreauthIPAddr(ip string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("ipaddr", ip)
	}
}

// PreauthTrustedDeviceToken sets the optional parameter for a Preauth request.
func PreauthTrustedDeviceToken(token string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("trusted_device_token", token)
	}
}

// Preauth calls POST /auth/v2/preauth
// See https://duo.com/docs/authapi#/preauth
// Use PreauthUserID to specify the user_id parameter.
// Use PreauthUsername to specify the username parameter.
// You must specify one of PreauthUserID or PreauthUsername, but not both.
// Use PreauthIPAddr to set the optional ipaddr parameter (the IP address of the client attempting authorization).
// Use PreauthTrustedDeviceToken to specify the optional trusted_device_token parameter.
func (c *Client) Preauth(options ...func(*url.Values)) (*PreauthResult, error) {
	opts := url.Values{}
	for _, o := range options {
		o(&opts)
	}
	_, body, err := c.SignedCall(http.MethodPost, "/auth/v2/preauth", opts, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}
	ret := &PreauthResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// AuthUserID sets the user_id parameter for an Auth request.
func AuthUserID(userID string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("user_id", userID)
	}
}

// AuthUsername sets the username parameter for an Auth request.
func AuthUsername(username string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("username", username)
	}
}

// AuthIPAddr sets the optional ipaddr parameter for an Auth request.
func AuthIPAddr(ip string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("ipaddr", ip)
	}
}

// AuthAsync sets the optional async parameter for an Auth request.
func AuthAsync() func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("async", "1")
	}
}

// AuthDevice sets the device parameter for an Auth request.
func AuthDevice(device string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("device", device)
	}
}

// AuthType sets the optional type parameter for an Auth request.
func AuthType(typ string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("type", typ)
	}
}

// AuthDisplayUsername sets the optional display_username parameter for an Auth request.
func AuthDisplayUsername(username string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("display_username", username)
	}
}

// AuthPushInfo sets the optional pushinfo parameter for an Auth request.
func AuthPushInfo(pushinfo string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("pushinfo", pushinfo)
	}
}

// AuthPasscode sets the passcode parameter for an Auth request.
func AuthPasscode(passcode string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("passcode", passcode)
	}
}

// AuthResult models responses containing authentication information.
type AuthResult struct {
	duoapi.BaseResult
	Response struct {
		// Synchronous
		Result             string
		Status             string
		StatusMsg          string `json:"status_msg"`
		TrustedDeviceToken string `json:"trusted_device_token"`
		// Asynchronous
		TxID string
	}
}

// Auth calls POST /auth/v2/auth
// See https://duo.com/docs/authapi#/auth
// Factor must be one of {"auto", "push", "passcode", "sms", "phone"}
// Use AuthUserID to specify the user_id.
// Use AuthUsername to specify the username.
// You must specify either AuthUserID or AuthUsername, but not both.
// Use AuthIPAddr to include the client's IP address.
// Use AuthAsync to toggle whether the call blocks for the user's response or not.
// If used asynchronously, get the auth status with the AuthStatus method.
// When using factor 'push', use AuthDevice to specify the device ID to push to.
// When using factor 'push', use AuthType to display some extra auth text to the user.
// When using factor 'push', use AuthDisplayUsername to display some extra text to the user.
// When using factor 'push', use AuthPushInfo to include some URL-encoded key/value pairs to display to the user.
// When using factor 'passcode', use AuthPasscode to specify the passcode entered by the user.
// When using factor 'sms' or 'phone', use AuthDevice to specify which device should receive the SMS or phone call.
func (c *Client) Auth(factor string, options ...func(*url.Values)) (*AuthResult, error) {
	params := url.Values{}
	for _, o := range options {
		o(&params)
	}
	params.Set("factor", factor)

	var apiOps []duoapi.DuoApiOption
	if _, ok := params["async"]; ok == true {
		apiOps = append(apiOps, duoapi.UseTimeout)
	}

	_, body, err := c.SignedCall(http.MethodPost, "/auth/v2/auth", params, apiOps...)
	if err != nil {
		return nil, err
	}

	ret := &AuthResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// AuthStatusResult models responses containing information about a previous auth request.
type AuthStatusResult struct {
	duoapi.BaseResult
	Response struct {
		Result             string
		Status             string
		StatusMsg          string `json:"status_msg"`
		TrustedDeviceToken string `json:"trusted_device_token"`
	}
}

// AuthStatus calls GET /auth/v2/auth_status
// See https://duo.com/docs/authapi#/auth_status
// When using the Auth method in async mode, pass the returned TxID to AuthStatus to check the result of an authentication attempt.
func (c *Client) AuthStatus(txID string) (*AuthStatusResult, error) {
	opts := url.Values{}
	opts.Set("txid", txID)

	_, body, err := c.SignedCall(http.MethodGet, "/auth/v2/auth_status", opts)
	if err != nil {
		return nil, err
	}

	ret := &AuthStatusResult{}
	if err = json.Unmarshal(body, ret); err != nil {
		return nil, err
	}
	return ret, nil
}
