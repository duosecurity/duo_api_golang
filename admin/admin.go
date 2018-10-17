package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/duosecurity/duo_api_golang"
)

// Client provides access to Duo's admin API.
type Client struct {
	duoapi.BaseClient
}

// New initializes an admin API Client struct.
func New(base duoapi.BaseClient) *Client {
	return &Client{base}
}

// User models a single user.
type User struct {
	Alias1            *string
	Alias2            *string
	Alias3            *string
	Alias4            *string
	Created           uint64
	Email             string
	FirstName         *string
	Groups            []Group
	LastDirectorySync *uint64 `json:"last_directory_sync"`
	LastLogin         *uint64 `json:"last_login"`
	LastName          *string
	Notes             string
	Phones            []Phone
	RealName          *string
	Status            string
	Tokens            []Token
	UserID            string `json:"user_id"`
	Username          string
}

// Group models a group to which users may belong.
type Group struct {
	Desc             string
	GroupID          string `json:"group_id"`
	MobileOTPEnabled bool   `json:"mobile_otp_enabled"`
	Name             string
	PushEnabled      bool `json:"push_enabled"`
	SMSEnabled       bool `json:"sms_enabled"`
	Status           string
	VoiceEnabled     bool `json:"voice_enabled"`
}

// Phone models a user's phone.
type Phone struct {
	Activated        bool
	Capabilities     []string
	Encrypted        string
	Extension        string
	Fingerprint      string
	Name             string
	Number           string
	PhoneID          string `json:"phone_id"`
	Platform         string
	Postdelay        string
	Predelay         string
	Screenlock       string
	SMSPasscodesSent bool
	Type             string
	Users            []User
}

// Token models a hardware security token.
type Token struct {
	TokenID  string `json:"token_id"`
	Type     string
	Serial   string
	TOTPStep *int `json:"totp_step"`
	Users    []User
}

// U2FToken models a U2F security token.
type U2FToken struct {
	DateAdded      uint64 `json:"date_added"`
	RegistrationID string `json:"registration_id"`
	User           *User
}

// StringResult models responses containing a simple string.
type StringResult struct {
	duoapi.BaseResult
	Response string
}

// User methods

// GetUsersLimit sets the limit parameter for a GetUsers request.
func GetUsersLimit(limit uint64) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("limit", strconv.FormatUint(limit, 10))
	}
}

// GetUsersOffset sets the offset parameter for a GetUsers request.
func GetUsersOffset(offset uint64) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("offset", strconv.FormatUint(offset, 10))
	}
}

// GetUsersUsername sets the username parameter for a GetUsers request.
func GetUsersUsername(name string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("username", name)
	}
}

// GetUsersResult models responses containing a list of users.
type GetUsersResult struct {
	duoapi.BaseResult
	Response []User
}

// GetUsers calls GET /admin/v1/users
// See https://duo.com/docs/adminapi#retrieve-users
func (c *Client) GetUsers(options ...func(*url.Values)) (*GetUsersResult, error) {
	params := url.Values{}
	for _, o := range options {
		o(&params)
	}

	_, body, err := c.SignedCall(http.MethodGet, "/admin/v1/users", params, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetUsersResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetUser calls GET /admin/v1/users/:user_id
// See https://duo.com/docs/adminapi#retrieve-user-by-id
func (c *Client) GetUser(userID string) (*GetUsersResult, error) {
	path := fmt.Sprintf("/admin/v1/users/%s", userID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetUsersResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetUserGroups calls GET /admin/v1/users/:user_id/groups
// See https://duo.com/docs/adminapi#retrieve-groups-by-user-id
func (c *Client) GetUserGroups(userID string) (*GetGroupsResult, error) {
	path := fmt.Sprintf("/admin/v1/users/%s/groups", userID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetGroupsResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetUserPhones calls GET /admin/v1/users/:user_id/phones
// See https://duo.com/docs/adminapi#retrieve-phones-by-user-id
func (c *Client) GetUserPhones(userID string) (*GetPhonesResult, error) {
	path := fmt.Sprintf("/admin/v1/users/%s/phones", userID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetPhonesResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetUserTokens calls GET /admin/v1/users/:user_id/tokens
// See https://duo.com/docs/adminapi#retrieve-hardware-tokens-by-user-id
func (c *Client) GetUserTokens(userID string) (*GetTokensResult, error) {
	path := fmt.Sprintf("/admin/v1/users/%s/tokens", userID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetTokensResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// AssociateUserToken calls POST /admin/v1/users/:user_id/tokens
// See https://duo.com/docs/adminapi#associate-hardware-token-with-user
func (c *Client) AssociateUserToken(userID, tokenID string) (*StringResult, error) {
	path := fmt.Sprintf("/admin/v1/users/%s/tokens", userID)

	params := url.Values{}
	params.Set("token_id", tokenID)

	_, body, err := c.SignedCall(http.MethodPost, path, params, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &StringResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetUserU2FTokens calls GET /admin/v1/users/:user_id/u2ftokens
// See https://duo.com/docs/adminapi#retrieve-u2f-tokens-by-user-id
func (c *Client) GetUserU2FTokens(userID string) (*GetU2FTokensResult, error) {
	path := fmt.Sprintf("/admin/v1/users/%s/u2ftokens", userID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetU2FTokensResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Group methods

// GetGroupsResult models responses containing a list of groups.
type GetGroupsResult struct {
	duoapi.BaseResult
	Response []Group
}

// GetGroups calls GET /admin/v1/groups
// See https://duo.com/docs/adminapi#retrieve-groups
func (c *Client) GetGroups() (*GetGroupsResult, error) {
	_, body, err := c.SignedCall(http.MethodGet, "/admin/v1/groups", nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetGroupsResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetGroupResult models responses containing a single group.
type GetGroupResult struct {
	duoapi.BaseResult
	Response Group
}

// GetGroup calls GET /admin/v2/group/:group_id
// See https://duo.com/docs/adminapi#get-group-info
func (c *Client) GetGroup(groupID string) (*GetGroupResult, error) {
	path := fmt.Sprintf("/admin/v2/groups/%s", groupID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetGroupResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Phone methods

// GetPhonesLimit sets the limit parameter for a GetPhones request.
func GetPhonesLimit(limit uint64) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("limit", strconv.FormatUint(limit, 10))
	}
}

// GetPhonesOffset sets the offset parameter for a GetPhones request.
func GetPhonesOffset(offset uint64) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("offset", strconv.FormatUint(offset, 10))
	}
}

// GetPhonesNumber sets the number parameter for a GetPhones request.
func GetPhonesNumber(number string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("number", number)
	}
}

// GetPhonesExtension sets the extension parameter for a GetPhones request.
func GetPhonesExtension(ext string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("extension", ext)
	}
}

// GetPhonesResult models responses containing a list of phones.
type GetPhonesResult struct {
	duoapi.BaseResult
	Response []Phone
}

// GetPhones calls GET /admin/v1/phones
// See https://duo.com/docs/adminapi#phones
func (c *Client) GetPhones(options ...func(*url.Values)) (*GetPhonesResult, error) {
	params := url.Values{}
	for _, o := range options {
		o(&params)
	}

	_, body, err := c.SignedCall(http.MethodGet, "/admin/v1/phones", params, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetPhonesResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetPhoneResult models responses containing a single phone.
type GetPhoneResult struct {
	duoapi.BaseResult
	Response Phone
}

// GetPhone calls GET /admin/v1/phones/:phone_id
// See https://duo.com/docs/adminapi#retrieve-phone-by-id
func (c *Client) GetPhone(phoneID string) (*GetPhoneResult, error) {
	path := fmt.Sprintf("/admin/v1/phones/%s", phoneID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetPhoneResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Token methods

// GetTokensTypeAndSerial sets the type and serial parameters for a GetTokens request.
func GetTokensTypeAndSerial(typ, serial string) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("type", typ)
		opts.Set("serial", serial)
	}
}

// GetTokensResult models responses containing a list of tokens.
type GetTokensResult struct {
	duoapi.BaseResult
	Response []Token
}

// GetTokens calls GET /admin/v1/tokens
// See https://duo.com/docs/adminapi#retrieve-hardware-tokens
func (c *Client) GetTokens(options ...func(*url.Values)) (*GetTokensResult, error) {
	params := url.Values{}
	for _, o := range options {
		o(&params)
	}

	_, body, err := c.SignedCall(http.MethodGet, "/admin/v1/tokens", params, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetTokensResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetTokenResult models responses containing a single token.
type GetTokenResult struct {
	duoapi.BaseResult
	Response Token
}

// GetToken calls GET /admin/v1/tokens/:token_id
// See https://duo.com/docs/adminapi#retrieve-hardware-tokens
func (c *Client) GetToken(tokenID string) (*GetTokenResult, error) {
	path := fmt.Sprintf("/admin/v1/tokens/%s", tokenID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetTokenResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// U2F token methods

// GetU2FTokensLimit sets the limit parameter for a GetU2FTokens request.
func GetU2FTokensLimit(limit uint64) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("limit", strconv.FormatUint(limit, 10))
	}
}

// GetU2FTokensOffset sets the offset parameter for a GetU2FTokens request.
func GetU2FTokensOffset(offset uint64) func(*url.Values) {
	return func(opts *url.Values) {
		opts.Set("offset", strconv.FormatUint(offset, 10))
	}
}

// GetU2FTokensResult models responses containing a list of U2F tokens.
type GetU2FTokensResult struct {
	duoapi.BaseResult
	Response []U2FToken
}

// GetU2FTokens calls GET /admin/v1/u2ftokens
// See https://duo.com/docs/adminapi#retrieve-u2f-tokens
func (c *Client) GetU2FTokens(options ...func(*url.Values)) (*GetU2FTokensResult, error) {
	params := url.Values{}
	for _, o := range options {
		o(&params)
	}

	_, body, err := c.SignedCall(http.MethodGet, "/admin/v1/u2ftokens", params, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetU2FTokensResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetU2FToken calls GET /admin/v1/u2ftokens/:registration_id
// See https://duo.com/docs/adminapi#retrieve-u2f-token-by-id
func (c *Client) GetU2FToken(registrationID string) (*GetU2FTokensResult, error) {
	path := fmt.Sprintf("/admin/v1/u2ftokens/%s", registrationID)

	_, body, err := c.SignedCall(http.MethodGet, path, nil, duoapi.UseTimeout)
	if err != nil {
		return nil, err
	}

	result := &GetU2FTokensResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
