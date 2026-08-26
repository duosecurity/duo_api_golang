package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	duoapi "github.com/duosecurity/duo_api_golang"
)

// maxLogV1PageSize sets 1000 as the maximum page size for API V1 log endpoints.
const maxLogV1PageSize = 1000

/*
 * V2 Logs
 */

// LogListV2Metadata holds pagination metadata for API V2 log endpoints.
type LogListV2Metadata struct {
	NextOffset []string `json:"next_offset"`
}

// GetNextOffset uses response metadata to return an option that will configure a request to fetch the next page of logs. It returns nil when no more logs can be fetched.
func (metadata LogListV2Metadata) GetNextOffset() func(params *url.Values) {
	offset := strings.Join(metadata.NextOffset, ",")
	if offset == "" {
		return nil
	}
	return func(params *url.Values) {
		params.Set("next_offset", offset)
	}
}

// V2 Auth Logs

// AuthLogResult is the structured JSON result of GetAuthLogs (for the V2 API).
type AuthLogResult struct {
	duoapi.StatResult
	Response AuthLogList `json:"response"`
}

// An AuthLog retrieved from https://duo.com/docs/adminapi#authentication-logs
type AuthLog struct {
	AccessDevice AccessDevice `json:"access_device"`
	Alias        string       `json:"alias"`
	Application  Application  `json:"application"`
	AuthDevice   AuthDevice   `json:"auth_device"`
	Email        string       `json:"email"`
	EventType    string       `json:"event_type"`
	Factor       string       `json:"factor"`
	ISOTimestamp time.Time    `json:"isotimestamp"`
	OODSoftware  string       `json:"ood_software"`
	Reason       string       `json:"reason"`
	Result       string       `json:"result"`
	Timestamp    int64        `json:"timestamp"`
	TxID         string       `json:"txid"`
	User         UserV2       `json:"user"`
}

// AccessDevice models a device that user uses to authenticate themselves.
type AccessDevice struct {
	Browser             string   `json:"browser"`
	BrowserVersion      string   `json:"browser_version"`
	FlashVersion        string   `json:"flash_version"`
	Hostname            string   `json:"hostname"`
	IP                  string   `json:"ip"`
	IsEncryptionEnabled string   `json:"is_encryption_enabled"`
	IsFirewallEnabled   string   `json:"is_firewall_enabled"`
	IsPasswordSet       string   `json:"is_password_set"`
	JavaVersion         string   `json:"java_version"`
	Location            Location `json:"location"`
	OS                  string   `json:"os"`
	OSVersion           string   `json:"os_version"`
	SecurityAgents      string   `json:"security_agents"`
}

// Application models information about the accessed application.
type Application struct {
	Key  string
	Name string
}

// Location represents a location where the user authenticates themselves.
type Location struct {
	City    string `json:"city"`
	Country string `json:"country"`
	State   string `json:"state"`
}

// AuthDevice models information about the device used to approve or
// deny authentication.
type AuthDevice struct {
	IP       string   `json:"ip"`
	Location Location `json:"location"`
	Name     string   `json:"name"`
}

// UserV2 models information about the authenticating user.
type UserV2 struct {
	Groups []string `json:"groups"`
	Key    string   `json:"key"`
	Name   string   `json:"name"`
}

// An AuthLogList holds retrieved logs and V2 metadata used for pagination.
type AuthLogList struct {
	Metadata LogListV2Metadata `json:"metadata"`
	Logs     []AuthLog         `json:"authlogs"`
}

// GetAuthLogs retrieves a page of authentication logs within the time range starting at mintime and ending at mintime + window. It relies on the option provided by AuthLogResult.Metadata.GetNextOffset() for pagination.
// Calls GET /admin/v2/logs/authentication
// See https://duo.com/docs/adminapi#authentication-logs
func (c *Client) GetAuthLogs(mintime time.Time, window time.Duration, options ...func(*url.Values)) (*AuthLogResult, error) {
	// Format mintime & maxtime parameters
	minMs := mintime.UnixNano() / int64(time.Millisecond)
	maxMs := mintime.Add(window).UnixNano() / int64(time.Millisecond)
	mintimeStr := strconv.FormatInt(minMs, 10)
	maxtimeStr := strconv.FormatInt(maxMs, 10)

	// Request defaults
	params := url.Values{
		"mintime": []string{mintimeStr},
		"maxtime": []string{maxtimeStr},
	}

	// Configure request with additional options
	for _, opt := range options {
		opt(&params)
	}

	// Retrieve page of authentication logs
	resp, body, err := c.SignedCall(
		http.MethodGet,
		"/admin/v2/logs/authentication",
		params,
	)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid HTTP response code from Duo API: [%d] %s", resp.StatusCode, resp.Status)
	}

	// Unmarshal received JSON into expected structure
	result := &AuthLogResult{}
	if err = json.Unmarshal(body, result); err != nil {
		return nil, err
	}

	return result, nil
}

/*
 * V1 Logs
 */

// parseLogV1Timestamp attempts to coerce the timestamp field of a log into a time.Time
func parseLogV1Timestamp(log map[string]interface{}) (time.Time, error) {
	var timestamp time.Time

	// Skip nil logs
	if log == nil {
		return timestamp, fmt.Errorf("cannot determine timestamp of nil log")
	}

	// Skip logs without a timestamp
	untypedTimestamp, ok := log["timestamp"]
	if !ok || untypedTimestamp == nil {
		return timestamp, fmt.Errorf("failed to parse value for timestamp field from log data")
	}

	// Skip logs with an invalid timestamp format
	switch num := untypedTimestamp.(type) {
	case float64:
		timestamp = time.Unix(int64(num), 0)
		break
	case int:
		timestamp = time.Unix(int64(num), 0)
		break
	case int32:
		timestamp = time.Unix(int64(num), 0)
		break
	case int64:
		timestamp = time.Unix(num, 0)
		break
	default:
		return timestamp, fmt.Errorf("received non-integer value in parsed timestamp field from log data")
	}

	// Skip logs with zero value timestamp
	if timestamp.IsZero() {
		return timestamp, fmt.Errorf("timestamp parsed from log data is zero")
	}

	return timestamp, nil
}

// getLogListV1NextOffset provides an option for pagination based on log timestamps. It returns nil when no more logs can be fetched.
func getLogListV1NextOffset(end time.Time, timestamps ...time.Time) func(params *url.Values) {
	// Receiving less than a full page indicates there are no more pages to fetch.
	if len(timestamps) < maxLogV1PageSize {
		return nil
	}

	// Determine min and max timestamps
	var max time.Time
	var min time.Time

	for _, timestamp := range timestamps {
		// Skip logs with zero value for timestamp
		if timestamp.IsZero() {
			continue
		}

		// We've collected a superset of logs for the time range, no next fetch
		if timestamp.After(end) {
			return nil
		}

		// Track maximum timestamp
		if timestamp.After(max) {
			max = timestamp
		}

		// Track minimum timestamp
		if min.IsZero() || timestamp.Before(min) {
			min = timestamp
		}
	}

	// Next mintime should be the maximum timestamp of the collected logs
	next := max

	// Entire page has same timestamp, increment to avoid infinitely fetching logs
	if min.Equal(max) {
		next = next.Add(1 * time.Second)
	}

	// A next mintime of zero means there is no next timestamp to fetch
	if next.IsZero() {
		return nil
	}

	// Configures the mintime parameter of the next request that is the maximum timestamp of received logs (in seconds).
	return func(params *url.Values) {
		params.Set("mintime", fmt.Sprintf("%d", next.Unix()))
	}
}

// V1 Admin Logs

// AdminLogResult is the structured JSON result of GetAdminLogs (for the V1 API).
type AdminLogResult struct {
	duoapi.StatResult
	Logs AdminLogList `json:"response"`
}

// An AdminLog retrieved from https://duo.com/docs/adminapi#administrator-logs
// TODO: @Duo update this to be a struct based on the returned JSON structure of an admin log.
type AdminLog map[string]interface{}

// Timestamp parses and coerces the timestamp value of the log.
func (log AdminLog) Timestamp() (time.Time, error) {
	return parseLogV1Timestamp(log)
}

// An AdminLogList holds log entries and provides functionality used for pagination.
type AdminLogList []AdminLog

// GetNextOffset uses log timestamps to return an option that will configure a request to fetch the next page of logs. It returns nil when no more logs can be fetched.
func (logs AdminLogList) GetNextOffset(maxtime time.Time) func(params *url.Values) {
	// Receiving less than a full page indicates there are no more pages to fetch.
	if len(logs) < maxLogV1PageSize {
		return nil
	}

	// Gather log timestamps
	timestamps := make([]time.Time, 0, len(logs))
	for _, log := range logs {
		ts, err := log.Timestamp()
		if err != nil {
			continue
		}
		timestamps = append(timestamps, ts)
	}

	return getLogListV1NextOffset(maxtime, timestamps...)
}

// GetAdminLogs retrieves a page of admin logs with timestamps starting at mintime. It relies on the option provided by AdminLogResult.Logs.GetNextOffset() for pagination.
// Calls GET /admin/v1/logs/administrator
// See https://duo.com/docs/adminapi#administrator-logs
func (c *Client) GetAdminLogs(mintime time.Time, options ...func(*url.Values)) (*AdminLogResult, error) {
	// Format mintime parameter
	min := mintime.UnixNano() / int64(time.Second)
	mintimeStr := strconv.FormatInt(min, 10)

	// Request defaults
	params := url.Values{
		"mintime": []string{mintimeStr},
	}

	// Configure request with additional options
	for _, opt := range options {
		opt(&params)
	}

	// Retrieve page of admin logs
	resp, body, err := c.SignedCall(
		http.MethodGet,
		"/admin/v1/logs/administrator",
		params,
	)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid HTTP response code from Duo API: [%d] %s", resp.StatusCode, resp.Status)
	}

	// Unmarshal received JSON into expected structure
	result := &AdminLogResult{}
	if err = json.Unmarshal(body, result); err != nil {
		return nil, err
	}

	return result, nil
}

// V1 Telephony Logs

// TelephonyLogResult is the structured JSON result of GetTelephonyLogs (for the V1 API).
type TelephonyLogResult struct {
	duoapi.StatResult
	Logs TelephonyLogList `json:"response"`
}

// A TelephonyLog retrieved from https://duo.com/docs/adminapi#telephony-logs
// TODO: @Duo update this to be a struct based on the returned JSON structure of a telephony log.
type TelephonyLog map[string]interface{}

// Timestamp parses and coerces the timestamp value of the log.
func (log TelephonyLog) Timestamp() (time.Time, error) {
	return parseLogV1Timestamp(log)
}

// An TelephonyLogList holds log entries and provides functionality used for pagination.
type TelephonyLogList []TelephonyLog

// GetNextOffset uses log timestamps to return an option that will configure a request to fetch the next page of logs. It returns nil when no more logs can be fetched.
func (logs TelephonyLogList) GetNextOffset(maxtime time.Time) func(params *url.Values) {
	// Receiving less than a full page indicates there are no more pages to fetch.
	if len(logs) < maxLogV1PageSize {
		return nil
	}

	// Gather log timestamps
	timestamps := make([]time.Time, 0, len(logs))
	for _, log := range logs {
		ts, err := log.Timestamp()
		if err != nil {
			continue
		}
		timestamps = append(timestamps, ts)
	}

	return getLogListV1NextOffset(maxtime, timestamps...)
}

// GetTelephonyLogs retrieves a page of telephony logs with timestamps starting at mintime. It relies on the option provided by TelephonyLogResult.Logs.GetNextOffset() for pagination.
// Calls GET /admin/v1/logs/telephony
// See https://duo.com/docs/adminapi#telephony-logs
func (c *Client) GetTelephonyLogs(mintime time.Time, options ...func(*url.Values)) (*TelephonyLogResult, error) {
	// Format mintime parameter
	min := mintime.UnixNano() / int64(time.Second)
	mintimeStr := strconv.FormatInt(min, 10)

	// Request defaults
	params := url.Values{
		"mintime": []string{mintimeStr},
	}

	// Configure request with additional options
	for _, opt := range options {
		opt(&params)
	}

	// Retrieve page of telephony logs
	resp, body, err := c.SignedCall(
		http.MethodGet,
		"/admin/v1/logs/telephony",
		params,
	)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid HTTP response code from Duo API: [%d] %s", resp.StatusCode, resp.Status)
	}

	// Unmarshal received JSON into expected structure
	result := &TelephonyLogResult{}
	if err = json.Unmarshal(body, result); err != nil {
		return nil, err
	}

	return result, nil
}
