package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

/*
 * Logs
 */

// TestLogListV2Metadata ensures that the next offset is properly configured based on known metadata.
func TestLogListV2Metadata(t *testing.T) {
	page := LogListV2Metadata{
		NextOffset: []string{"1532951895000", "af0ba235-0b33-23c8-bc23-a31aa0231de8"},
	}
	nextOffset := page.GetNextOffset()
	if nextOffset == nil {
		t.Fatalf("Expected option to configure next offset, got nil")
	}
	params := url.Values{}
	nextOffset(&params)
	if nextParam := params.Get("next_offset"); nextParam != "1532951895000,af0ba235-0b33-23c8-bc23-a31aa0231de8" {
		t.Fatalf("Expected option to configure next offset to be '1532951895000,af0ba235-0b33-23c8-bc23-a31aa0231de8', got %q", nextParam)
	}

	lastPage := LogListV2Metadata{}
	if lastPage.GetNextOffset() != nil {
		t.Errorf("Expected nil option to represent no more available logs, got a non-nil option")
	}
}

// TestLogListV2Metadata ensures that timestamps are properly parsed from log data.
func TestParseLogV1Timestamp(t *testing.T) {
	validLog := map[string]interface{}{
		"timestamp": 1346172820,
	}
	timestamp, err := parseLogV1Timestamp(validLog)
	if err != nil {
		t.Errorf("Failed to parse log timestamp: %v", err)
	}
	if expectedTs := time.Unix(1346172820, 0); !timestamp.Equal(expectedTs) {
		t.Errorf("Parsed incorrect value for log timestamp, expected %v but got: %v", expectedTs, timestamp)
	}
}

// getAuthLogsResponse is an example response from the Duo API documentation example: https://duo.com/docs/adminapi#authentication-logs
const getAuthLogsResponse = `{
    "response": {
        "authlogs": [
            {
                "access_device": {
                    "browser": "Chrome",
                    "browser_version": "67.0.3396.99",
                    "flash_version": "uninstalled",
                    "hostname": "null",
                    "ip": "169.232.89.219",
                    "java_version": "uninstalled",
                    "location": {
                        "city": "Ann Arbor",
                        "country": "United States",
                        "state": "Michigan"
                    },
                    "os": "Mac OS X",
                    "os_version": "10.14.1"
                },
                "application": {
                    "key": "DIY231J8BR23QK4UKBY8",
                    "name": "Microsoft Azure Active Directory"
                },
                "auth_device": {
                    "ip": "192.168.225.254",
                    "location": {
                        "city": "Ann Arbor",
                        "country": "United States",
                        "state": "Michigan"
                    },
                    "name": "My iPhone X (734-555-2342)"
                },
                "event_type": "authentication",
                "factor": "duo_push",
                "reason": "user_approved",
                "result": "success",
                "timestamp": 1532951962,
                "trusted_endpoint_status": "not trusted",
                "txid": "340a23e3-23f3-23c1-87dc-1491a23dfdbb",
                "user": {
                    "key": "DU3KC77WJ06Y5HIV7XKQ",
                    "name": "narroway@example.com"
                }
            }
        ],
        "metadata": {
            "next_offset": [
                "1532951895000",
                "af0ba235-0b33-23c8-bc23-a31aa0231de8"
            ],
            "total_objects": 1
        }
    },
    "stat": "OK"
}`

// TestGetAuthLogs ensures proper functionality of the client.GetAuthLogs method.
func TestGetAuthLogs(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getAuthLogsResponse)
			last_request = r
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	lastMetadata := LogListV2Metadata{
		NextOffset: []string{"1532951920000", "b40ba235-0b33-23c8-bc23-a31aa0231db4"},
	}
	mintime := time.Unix(1532951960, 0)
	window := 5 * time.Second
	result, err := duo.GetAuthLogs(mintime, window, lastMetadata.GetNextOffset())

	if err != nil {
		t.Errorf("Unexpected error from GetAuthLogs call: %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if length := len(result.Response.Logs); length != 1 {
		t.Errorf("Expected 1 log, but got %d", length)
	}
	if txid := result.Response.Logs[0]["txid"]; txid != "340a23e3-23f3-23c1-87dc-1491a23dfdbb" {
		t.Errorf("Expected txid '340a23e3-23f3-23c1-87dc-1491a23dfdbb', but got %v", txid)
	}
	if next := result.Response.Metadata.GetNextOffset(); next == nil {
		t.Errorf("Expected metadata.GetNextOffset option to configure pagination for next request, got nil")
	}

	request_query := last_request.URL.Query()
	if qMintime := request_query["mintime"][0]; qMintime != "1532951960000" {
		t.Errorf("Expected to see a mintime of 153295196000 in request, but got %q", qMintime)
	}
	if qMaxtime := request_query["maxtime"][0]; qMaxtime != "1532951965000" {
		t.Errorf("Expected to see a maxtime of 153295196500 in request, but got %q", qMaxtime)
	}
	if qNextOffset := request_query["next_offset"][0]; qNextOffset != "1532951920000,b40ba235-0b33-23c8-bc23-a31aa0231db4" {
		t.Errorf("Expected to see a next_offset of 1532951920000,b40ba235-0b33-23c8-bc23-a31aa0231db4 in request, but got %q", qNextOffset)
	}
}

// getAdminLogsResponse is an example response from the Duo API documentation example: https://duo.com/docs/adminapi#administrator-logs
const getAdminLogsResponse = `{
	"stat": "OK",
	"response": [{
		"action": "user_update",
		"description": "{\"notes\": \"Joe asked for their nickname to be displayed instead of Joseph.\", \"realname\": \"Joe Smith\"}",
		"object": "jsmith",
		"timestamp": 1346172820,
		"username": "admin"
	},
	{
		"action": "admin_login_error",
		"description": "{\"ip_address\": \"10.1.23.116\", \"error\": \"SAML login is disabled\", \"email\": \"narroway@example.com\"}",
		"object": null,
		"timestamp": 1446172820,
		"username": ""
	}]
  }`

// TestGetAdminLogs ensures proper functionality of the client.GetAdminLogs method.
func TestGetAdminLogs(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getAdminLogsResponse)
			last_request = r
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	mintime := time.Unix(1346172815, 0)
	maxtime := mintime.Add(time.Second * 10)
	result, err := duo.GetAdminLogs(mintime)

	if err != nil {
		t.Errorf("Unexpected error from GetAdminLogs call: %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if length := len(result.Logs); length != 2 {
		t.Errorf("Expected 2 logs, but got %d", length)
	}
	timestamp, err := result.Logs[0].Timestamp()
	if err != nil {
		t.Errorf("Failed to parse timestamp timestamp: %v", err)
	}
	if expectedTs := time.Unix(1346172820, 0); !expectedTs.Equal(timestamp) {
		t.Errorf("Expected timestamp %v, but got: %v", expectedTs, timestamp)
	}
	if next := result.Logs.GetNextOffset(maxtime); next != nil {
		t.Errorf("Expected no next page available, got non-nil option")
	}

	request_query := last_request.URL.Query()
	if qMintime := request_query["mintime"][0]; qMintime != "1346172815" {
		t.Errorf("Expected to see a mintime of 1346172815 in request, but got %q", qMintime)
	}
}

// TestAdminLogsNextOffset ensures proper pagination functionality for AdminLogResult
func TestAdminLogsNextOffset(t *testing.T) {
	maxtime := time.Unix(1346172825, 0)

	// Ensure < 1000 logs returns none
	result := &AdminLogResult{}
	if next := result.Logs.GetNextOffset(maxtime); next != nil {
		t.Errorf("Expected no next page available, got non-nil option")
	}

	// Ensure mintime == maxtime returns maxtime + 1
	logs := make([]AdminLog, 0, 1000)
	for i := 0; i < 1000; i++ {
		logs = append(logs, AdminLog{"timestamp": 1346172816})
	}
	result.Logs = AdminLogList(logs)
	params := &url.Values{}
	result.Logs.GetNextOffset(maxtime)(params)
	if newMintime := params.Get("mintime"); newMintime != "1346172817" {
		t.Errorf("Expected new mintime to be 1346172817, got: %v", newMintime)
	}

	// Ensure single maxtime returns maxtime
	result.Logs[0] = AdminLog{"timestamp": 1346172820}
	params = &url.Values{}
	result.Logs.GetNextOffset(maxtime)(params)
	if newMintime := params.Get("mintime"); newMintime != "1346172820" {
		t.Errorf("Expected new mintime to be 1346172820, got: %v", newMintime)
	}
}

// getTelephonyLogsResponse is an example response from the Duo API documentation example: https://duo.com/docs/adminapi#telephony-logs
const getTelephonyLogsResponse = `{
	"stat": "OK",
	"response": [{
		"context": "authentication",
		"credits": 1,
		"phone": "+15035550100",
		"timestamp": 1346172697,
		"type": "sms"
	}]
  }`

// TestGetTelephonyLogs ensures proper functionality of the client.GetTelephonyLogs method.
func TestGetTelephonyLogs(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getTelephonyLogsResponse)
			last_request = r
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	mintime := time.Unix(1346172600, 0)
	maxtime := mintime.Add(time.Second * 10)
	result, err := duo.GetTelephonyLogs(mintime)

	if err != nil {
		t.Errorf("Unexpected error from GetTelephonyLogs call: %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if length := len(result.Logs); length != 1 {
		t.Errorf("Expected 1 logs, but got %d", length)
	}
	timestamp, err := result.Logs[0].Timestamp()
	if err != nil {
		t.Errorf("Failed to parse timestamp timestamp: %v", err)
	}
	if expectedTs := time.Unix(1346172697, 0); !expectedTs.Equal(timestamp) {
		t.Errorf("Expected timestamp %v, but got: %v", expectedTs, timestamp)
	}
	if next := result.Logs.GetNextOffset(maxtime); next != nil {
		t.Errorf("Expected no next page available, got non-nil option")
	}

	request_query := last_request.URL.Query()
	if qMintime := request_query["mintime"][0]; qMintime != "1346172600" {
		t.Errorf("Expected to see a mintime of 1346172600 in request, but got %q", qMintime)
	}
}

// TestTelephonyLogsNextOffset ensures proper pagination functionality for TelephonyLogResult
func TestTelephonyLogsNextOffset(t *testing.T) {
	maxtime := time.Unix(1346172825, 0)

	// Ensure < 1000 logs returns none
	result := &TelephonyLogResult{}
	if next := result.Logs.GetNextOffset(maxtime); next != nil {
		t.Errorf("Expected no next page available, got non-nil option")
	}

	// Ensure mintime == maxtime returns maxtime + 1
	logs := make([]TelephonyLog, 0, 1000)
	for i := 0; i < 1000; i++ {
		logs = append(logs, TelephonyLog{"timestamp": 1346172816})
	}
	result.Logs = TelephonyLogList(logs)
	params := &url.Values{}
	result.Logs.GetNextOffset(maxtime)(params)
	if newMintime := params.Get("mintime"); newMintime != "1346172817" {
		t.Errorf("Expected new mintime to be 1346172817, got: %v", newMintime)
	}

	// Ensure single maxtime returns maxtime
	result.Logs[0] = TelephonyLog{"timestamp": 1346172820}
	params = &url.Values{}
	result.Logs.GetNextOffset(maxtime)(params)
	if newMintime := params.Get("mintime"); newMintime != "1346172820" {
		t.Errorf("Expected new mintime to be 1346172820, got: %v", newMintime)
	}
}
