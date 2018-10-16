package admin

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/duosecurity/duo_api_golang"
)

func buildAdminClient(url string, proxy func(*http.Request) (*url.URL, error)) *Client {
	ikey := "eyekey"
	skey := "esskey"
	host := strings.Split(url, "//")[1]
	userAgent := "GoTestClient"
	base := duoapi.New(ikey, skey, host, userAgent, duoapi.SetTimeout(1*time.Second), duoapi.SetInsecure(), duoapi.SetProxy(proxy))
	return New(*base)
}

func getBodyParams(r *http.Request) (url.Values, error) {
	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return url.Values{}, err
	}
	reqParams, err := url.ParseQuery(string(body))
	return reqParams, err
}

const getUsersResponse = `{
	"stat": "OK",
	"response": [{
		"alias1": "joe.smith",
		"alias2": "jsmith@example.com",
		"alias3": null,
		"alias4": null,
		"created": 1489612729,
		"email": "jsmith@example.com",
		"firstname": "Joe",
		"groups": [{
			"desc": "People with hardware tokens",
			"name": "token_users"
		}],
		"last_directory_sync": 1508789163,
		"last_login": 1343921403,
		"lastname": "Smith",
		"notes": "",
		"phones": [{
			"phone_id": "DPFZRS9FB0D46QFTM899",
			"number": "+15555550100",
			"extension": "",
			"name": "",
			"postdelay": null,
			"predelay": null,
			"type": "Mobile",
			"capabilities": [
				"sms",
				"phone",
				"push"
			],
			"platform": "Apple iOS",
			"activated": false,
			"sms_passcodes_sent": false
		}],
		"realname": "Joe Smith",
		"status": "active",
		"tokens": [{
			"serial": "0",
			"token_id": "DHIZ34ALBA2445ND4AI2",
			"type": "d1"
		}],
		"user_id": "DU3RP9I2WOC59VZX672N",
		"username": "jsmith"
	}]
}`

func TestGetUsers(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUsersResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUsers()
	if err != nil {
		t.Errorf("Unexpected error from GetUsers call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 1 {
		t.Errorf("Expected 1 user, but got %d", len(result.Response))
	}
	if result.Response[0].UserID != "DU3RP9I2WOC59VZX672N" {
		t.Errorf("Expected user ID DU3RP9I2WOC59VZX672N, but got %s", result.Response[0].UserID)
	}
}

func TestGetUser(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUsersResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUser("DU3RP9I2WOC59VZX672N")
	if err != nil {
		t.Errorf("Unexpected error from GetUser call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 1 {
		t.Errorf("Expected 1 user, but got %d", len(result.Response))
	}
	if result.Response[0].UserID != "DU3RP9I2WOC59VZX672N" {
		t.Errorf("Expected user ID DU3RP9I2WOC59VZX672N, but got %s", result.Response[0].UserID)
	}
}

const getGroupsResponse = `{
	"response": [{
		"desc": "This is group A",
		"group_id": "DGXXXXXXXXXXXXXXXXXA",
		"name": "Group A",
		"push_enabled": true,
		"sms_enabled": true,
		"status": "active",
		"voice_enabled": true,
		"mobile_otp_enabled": true
	},
	{
		"desc": "This is group B",
		"group_id": "DGXXXXXXXXXXXXXXXXXB",
		"name": "Group B",
		"push_enabled": true,
		"sms_enabled": true,
		"status": "active",
		"voice_enabled": true,
		"mobile_otp_enabled": true
	}],
	"stat": "OK"
}`

func TestGetUserGroups(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getGroupsResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserGroups("DU3RP9I2WOC59VZX672N")
	if err != nil {
		t.Errorf("Unexpected error from GetUserGroups call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 2 {
		t.Errorf("Expected 2 groups, but got %d", len(result.Response))
	}
	if result.Response[0].GroupID != "DGXXXXXXXXXXXXXXXXXA" {
		t.Errorf("Expected group ID DGXXXXXXXXXXXXXXXXXA, but got %s", result.Response[0].GroupID)
	}
}

const getUserPhonesResponse = `{
	"stat": "OK",
	"response": [{
		"activated": false,
		"capabilities": [
			"sms",
			"phone",
			"push"
		],
		"extension": "",
		"name": "",
		"number": "+15035550102",
		"phone_id": "DPFZRS9FB0D46QFTM890",
		"platform": "Apple iOS",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Mobile"
	},
	{
		"activated": false,
		"capabilities": [
			"phone"
		],
		"extension": "",
		"name": "",
		"number": "+15035550103",
		"phone_id": "DPFZRS9FB0D46QFTM891",
		"platform": "Unknown",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Landline"
	}]
}`

func TestGetUserPhones(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUserPhonesResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserPhones("DU3RP9I2WOC59VZX672N")
	if err != nil {
		t.Errorf("Unexpected error from GetUserPhones call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 2 {
		t.Errorf("Expected 2 phones, but got %d", len(result.Response))
	}
	if result.Response[0].PhoneID != "DPFZRS9FB0D46QFTM890" {
		t.Errorf("Expected phone ID DPFZRS9FB0D46QFTM890, but got %s", result.Response[0].PhoneID)
	}
}

const getUserTokensResponse = `{
	"stat": "OK",
	"response": [{
		"type": "d1",
		"serial": "0",
		"token_id": "DHEKH0JJIYC1LX3AZWO4"
	},
	{
		"type": "d1",
		"serial": "7",
		"token_id": "DHUNT3ZVS3ACF8AEV2WG",
		"totp_step": null
	}]
}`

func TestGetUserTokens(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUserTokensResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserTokens("DU3RP9I2WOC59VZX672N")
	if err != nil {
		t.Errorf("Unexpected error from GetUserTokens call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 2 {
		t.Errorf("Expected 2 tokens, but got %d", len(result.Response))
	}
	if result.Response[0].TokenID != "DHEKH0JJIYC1LX3AZWO4" {
		t.Errorf("Expected token ID DHEKH0JJIYC1LX3AZWO4, but got %s", result.Response[0].TokenID)
	}
}

const associateUserTokenResponse = `{
	"stat": "OK",
	"response": ""
}`

func TestAssociateUserToken(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, associateUserTokenResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.AssociateUserToken("DU3RP9I2WOC59VZX672N", "DHEKH0JJIYC1LX3AZWO4")
	if err != nil {
		t.Errorf("Unexpected error from AssociateUserToken call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 0 {
		t.Errorf("Expected empty response, but got %s", result.Response)
	}
}

const getUserU2FTokensResponse = `{
	"stat": "OK",
	"response": [{
		"date_added": 1444678994,
		"registration_id": "D21RU6X1B1DF5P54B6PV"
	}]
}`

func TestGetUserU2FTokens(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUserU2FTokensResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserU2FTokens("DU3RP9I2WOC59VZX672N")
	if err != nil {
		t.Errorf("Unexpected error from GetUserU2FTokens call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 1 {
		t.Errorf("Expected 1 token, but got %d", len(result.Response))
	}
	if result.Response[0].RegistrationID != "D21RU6X1B1DF5P54B6PV" {
		t.Errorf("Expected registration ID D21RU6X1B1DF5P54B6PV, but got %s", result.Response[0].RegistrationID)
	}
}

func TestGetGroups(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getGroupsResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetGroups()
	if err != nil {
		t.Errorf("Unexpected error from GetGroups call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 2 {
		t.Errorf("Expected 2 groups, but got %d", len(result.Response))
	}
	if result.Response[0].Name != "Group A" {
		t.Errorf("Expected group name Group A, but got %s", result.Response[0].Name)
	}
}

const getGroupResponse = `{
	"response": {
		"desc": "Group description",
		"group_id": "DGXXXXXXXXXXXXXXXXXX",
		"name": "Group Name",
		"push_enabled": true,
		"sms_enabled": true,
		"status": "active",
		"voice_enabled": true,
		"mobile_otp_enabled": true
	},
	"stat": "OK"
}`

func TestGetGroup(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getGroupResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetGroup("DGXXXXXXXXXXXXXXXXXX")
	if err != nil {
		t.Errorf("Unexpected error from GetGroups call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if result.Response.GroupID != "DGXXXXXXXXXXXXXXXXXX" {
		t.Errorf("Expected group ID DGXXXXXXXXXXXXXXXXXX, but got %s", result.Response.GroupID)
	}
	if !result.Response.PushEnabled {
		t.Errorf("Expected push to be enabled, but got %v", result.Response.PushEnabled)
	}
}

const getPhonesResponse = `{
	"stat": "OK",
	"response": [{
		"activated": true,
		"capabilities": [
			"push",
			"sms",
			"phone",
			"mobile_otp"
		],
		"encrypted": "Encrypted",
		"extension": "",
		"fingerprint": "Configured",
		"name": "",
		"number": "+15555550100",
		"phone_id": "DPFZRS9FB0D46QFTM899",
		"platform": "Google Android",
		"postdelay": "",
		"predelay": "",
		"screenlock": "Locked",
		"sms_passcodes_sent": false,
		"tampered": "Not tampered",
		"type": "Mobile",
		"users": [{
			"alias1": "joe.smith",
			"alias2": "jsmith@example.com",
			"alias3": null,
			"alias4": null,
			"email": "jsmith@example.com",
			"firstname": "Joe",
			"last_login": 1474399627,
			"lastname": "Smith",
			"notes": "",
			"realname": "Joe Smith",
			"status": "active",
			"user_id": "DUJZ2U4L80HT45MQ4EOQ",
			"username": "jsmith"
		}]
	}]
}`

func TestGetPhones(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getPhonesResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetPhones()
	if err != nil {
		t.Errorf("Unexpected error from GetPhones call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 1 {
		t.Errorf("Expected 1 phone, but got %d", len(result.Response))
	}
	if result.Response[0].PhoneID != "DPFZRS9FB0D46QFTM899" {
		t.Errorf("Expected phone ID DPFZRS9FB0D46QFTM899, but got %s", result.Response[0].PhoneID)
	}
}

const getPhoneResponse = `{
	"stat": "OK",
	"response": {
		"phone_id": "DPFZRS9FB0D46QFTM899",
		"number": "+15555550100",
		"name": "",
		"extension": "",
		"postdelay": null,
		"predelay": null,
		"type": "Mobile",
		"capabilities": [
			"sms",
			"phone",
			"push"
		],
		"platform": "Apple iOS",
		"activated": false,
		"sms_passcodes_sent": false,
		"users": [{
			"user_id": "DUJZ2U4L80HT45MQ4EOQ",
			"username": "jsmith",
			"alias1": "joe.smith",
			"alias2": "jsmith@example.com",
			"realname": "Joe Smith",
			"email": "jsmith@example.com",
			"status": "active",
			"last_login": 1343921403,
			"notes": ""
		}]
	}
}`

func TestGetPhone(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getPhoneResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetPhone("DPFZRS9FB0D46QFTM899")
	if err != nil {
		t.Errorf("Unexpected error from GetPhone call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if result.Response.PhoneID != "DPFZRS9FB0D46QFTM899" {
		t.Errorf("Expected phone ID DPFZRS9FB0D46QFTM899, but got %s", result.Response.PhoneID)
	}
}

const getTokensResponse = `{
	"stat": "OK",
	"response": [{
		"serial": "0",
		"token_id": "DHIZ34ALBA2445ND4AI2",
		"type": "d1",
		"totp_step": null,
		"users": [{
			"user_id": "DUJZ2U4L80HT45MQ4EOQ",
			"username": "jsmith",
			"alias1": "joe.smith",
			"alias2": "jsmith@example.com",
			"realname": "Joe Smith",
			"email": "jsmith@example.com",
			"status": "active",
			"last_login": 1343921403,
			"notes": ""
		}]
	}]
}`

func TestGetTokens(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getTokensResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetTokens()
	if err != nil {
		t.Errorf("Unexpected error from GetTokens call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 1 {
		t.Errorf("Expected 1 token, but got %d", len(result.Response))
	}
	if result.Response[0].TokenID != "DHIZ34ALBA2445ND4AI2" {
		t.Errorf("Expected token ID DHIZ34ALBA2445ND4AI2, but got %s", result.Response[0].TokenID)
	}
}

const getTokenResponse = `{
	"stat": "OK",
	"response": {
		"serial": "0",
		"token_id": "DHIZ34ALBA2445ND4AI2",
		"type": "d1",
		"totp_step": null,
		"users": [{
			"user_id": "DUJZ2U4L80HT45MQ4EOQ",
			"username": "jsmith",
			"alias1": "joe.smith",
			"alias2": "jsmith@example.com",
			"realname": "Joe Smith",
			"email": "jsmith@example.com",
			"status": "active",
			"last_login": 1343921403,
			"notes": ""
		}]
	}
}`

func TestGetToken(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getTokenResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetToken("DPFZRS9FB0D46QFTM899")
	if err != nil {
		t.Errorf("Unexpected error from GetToken call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if result.Response.TokenID != "DHIZ34ALBA2445ND4AI2" {
		t.Errorf("Expected token ID DHIZ34ALBA2445ND4AI2, but got %s", result.Response.TokenID)
	}
}

const getU2FTokensResponse = `{
	"stat": "OK",
	"response": [{
		"date_added": 1444678994,
		"registration_id": "D21RU6X1B1DF5P54B6PV",
		"user": {
			"alias1": "joe.smith",
			"alias2": "jsmith@example.com",
			"alias3": null,
			"alias4": null,
			"created": 1384275337,
			"email": "jsmith@example.com",
			"firstname": "Joe",
			"last_directory_sync": 1384275337,
			"last_login": 1514922986,
			"lastname": "Smith",
			"notes": "",
			"realname": "Joe Smith",
			"status": "active",
			"user_id": "DU3RP9I2WOC59VZX672N",
			"username": "jsmith"
		}
	}]
}`

func TestGetU2FTokens(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getU2FTokensResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetU2FTokens()
	if err != nil {
		t.Errorf("Unexpected error from GetU2FTokens call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 1 {
		t.Errorf("Expected 1 token, but got %d", len(result.Response))
	}
	if result.Response[0].RegistrationID != "D21RU6X1B1DF5P54B6PV" {
		t.Errorf("Expected registration ID D21RU6X1B1DF5P54B6PV, but got %s", result.Response[0].RegistrationID)
	}
}

func TestGetU2FToken(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getU2FTokensResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetU2FToken("D21RU6X1B1DF5P54B6PV")
	if err != nil {
		t.Errorf("Unexpected error from GetU2FToken call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 1 {
		t.Errorf("Expected 1 token, but got %d", len(result.Response))
	}
	if result.Response[0].RegistrationID != "D21RU6X1B1DF5P54B6PV" {
		t.Errorf("Expected registration ID D21RU6X1B1DF5P54B6PV, but got %s", result.Response[0].RegistrationID)
	}
}
