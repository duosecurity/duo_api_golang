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
// TODO: @Duo update this to be a struct based on the returned JSON structure of an authentication log.
type AuthLog map[string]interface{}

// An AuthLogList holds retreived logs and V2 metadata used for pagination.
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
