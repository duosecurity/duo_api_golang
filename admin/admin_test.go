package admin

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	duoapi "github.com/duosecurity/duo_api_golang"
)

func buildAdminClient(url string, proxy func(*http.Request) (*url.URL, error)) *Client {
	ikey := "eyekey"
	skey := "esskey"
	host := strings.Split(url, "//")[1]
	userAgent := "GoTestClient"
	base := duoapi.NewDuoApi(ikey, skey, host, userAgent, duoapi.SetTimeout(1*time.Second), duoapi.SetInsecure(), duoapi.SetProxy(proxy))
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
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 1
	},
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
			"model": "Apple iPhone",
			"activated": false,
			"last_seen": "2019-03-04T15:04:04",
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

const getUserResponse = `{
	"stat": "OK",
	"response": {
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
			"model": "Apple iPhone",
			"activated": false,
			"last_seen": "2019-03-04T15:04:04",
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
	}
}`

func TestUser_URLValues(t *testing.T) {
	type fields struct {
		Alias1            *string
		Alias2            *string
		Alias3            *string
		Alias4            *string
		Created           uint64
		Email             string
		FirstName         *string
		Groups            []Group
		LastDirectorySync *uint64
		LastLogin         *uint64
		LastName          *string
		Notes             string
		Phones            []Phone
		RealName          *string
		Status            string
		Tokens            []Token
		UserID            string
		Username          string
	}

	exAlias := "smith"

	tests := []struct {
		name   string
		fields fields
		want   url.Values
	}{
		{
			name: "Simple",
			fields: fields{
				Username: "jsmith",
				Status:   "active",
				Email:    "jsmith@example.com",
				Notes:    "this is a test user",
			},
			want: url.Values(map[string][]string{
				"username": {"jsmith"},
				"status":   {"active"},
				"email":    {"jsmith@example.com"},
				"notes":    {"this is a test user"},
			}),
		},
		{
			name: "Example with pointer",
			fields: fields{
				Alias1:   &exAlias,
				Username: "jsmith",
			},
			want: url.Values(map[string][]string{
				"alias1":   {"smith"},
				"username": {"jsmith"},
			}),
		},
		{
			name: "Untagged",
			fields: fields{
				Username: "jsmith",
				Created:  1234,
				Groups:   []Group{{Name: "group1"}},
				Phones:   []Phone{{Name: "phone1"}},
				Tokens:   []Token{{TokenID: "token1"}},
			},
			want: url.Values(map[string][]string{
				"username": {"jsmith"}},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{
				Alias1:            tt.fields.Alias1,
				Alias2:            tt.fields.Alias2,
				Alias3:            tt.fields.Alias3,
				Alias4:            tt.fields.Alias4,
				Created:           tt.fields.Created,
				Email:             tt.fields.Email,
				FirstName:         tt.fields.FirstName,
				Groups:            tt.fields.Groups,
				LastDirectorySync: tt.fields.LastDirectorySync,
				LastLogin:         tt.fields.LastLogin,
				LastName:          tt.fields.LastName,
				Notes:             tt.fields.Notes,
				Phones:            tt.fields.Phones,
				RealName:          tt.fields.RealName,
				Status:            tt.fields.Status,
				Tokens:            tt.fields.Tokens,
				UserID:            tt.fields.UserID,
				Username:          tt.fields.Username,
			}
			if got := u.URLValues(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("User.URLValues() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUsers(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUsersResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const createUserResponse = `{
	"stat": "OK",
	"response": {
		"alias1": null,
		"alias2": null,
		"alias3": null,
		"alias4": null,
		"created": 1489612729,
		"email": "jsmith@example.com",
		"firstname": null,
		"groups": [],
		"last_directory_sync": null,
		"last_login": null,
		"lastname": null,
		"notes": "",
		"phones": [],
		"realname": null,
		"status": "active",
		"tokens": [],
		"user_id": "DU3RP9I2WOC59VZX672N",
		"username": "jsmith"
	}
}`

func TestCreateUser(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, createUserResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	userToCreate := User{
		Username: "jsmith",
		Email:    "jsmith@example.com",
		Status:   "active",
	}

	result, err := duo.CreateUser(userToCreate.URLValues())
	if err != nil {
		t.Errorf("Unexpected error from CreateUser call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if result.Response.Username != userToCreate.Username {
		t.Errorf("Expected Username to be %s, but got %s", userToCreate.Username, result.Response.Username)
	}
	if result.Response.Email != userToCreate.Email {
		t.Errorf("Expected Email to be %s, but got %s", userToCreate.Email, result.Response.Email)
	}
}

const modifyUserResponse = `{
	"stat": "OK",
	"response": {
		"alias1": "joe.smith",
		"alias2": "jsmith@example.com",
		"alias3": null,
		"alias4": null,
		"created": 1489612729,
		"email": "jsmith-new@example.com",
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
	}
}`

func TestModifyUser(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, modifyUserResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	userToModify := User{
		UserID: "DU3RP9I2WOC59VZX672N",
		Email:  "jsmith-new@example.com",
	}

	result, err := duo.ModifyUser(userToModify.UserID, userToModify.URLValues())
	if err != nil {
		t.Errorf("Unexpected error from ModifyUser call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if result.Response.UserID != userToModify.UserID {
		t.Errorf("Expected UserID to be %s, but got %s", userToModify.UserID, result.Response.UserID)
	}
	if result.Response.Email != userToModify.Email {
		t.Errorf("Expected Email to be %s, but got %s", userToModify.Email, result.Response.Email)
	}
}

const deleteUserResponse = `{
	"stat": "OK",
	"response": ""
}`

func TestDeleteUser(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, deleteUserResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.DeleteUser("DU3RP9I2WOC59VZX672N")
	if err != nil {
		t.Errorf("Unexpected error from DeleteUser call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
}

const getUsersPage1Response = `{
	"stat": "OK",
	"metadata": {
		"prev_offset": null,
		"next_offset": 1,
		"total_objects": 2
	},
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
			"model": "Apple iPhone",
			"activated": false,
			"last_seen": "2019-03-04T15:04:04",
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

const getUsersPage2Response = `{
	"stat": "OK",
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 2
	},
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
			"model": "Apple iPhone",
			"activated": false,
			"last_seen": "2019-03-04T15:04:04",
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

func TestGetUsersMultipage(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getUsersPage1Response)
			} else {
				fmt.Fprintln(w, getUsersPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUsers()

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if result.Metadata.TotalObjects != "2" {
		t.Errorf("Expected total obects to be two, found %s", result.Metadata.TotalObjects)
	}

	if len(result.Response) != 2 {
		t.Errorf("Expected two users in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

const getEmptyPageArgsResponse = `{
	"stat": "OK",
	"metadata": {
		"prev_offset": null,
		"next_offset": 2,
		"total_objects": 2
	},
	"response": []
}`

func TestGetUserPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetUsers(func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

func TestGetUser(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUserResponse)
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
	if result.Response.UserID != "DU3RP9I2WOC59VZX672N" {
		t.Errorf("Expected user ID DU3RP9I2WOC59VZX672N, but got %s", result.Response.UserID)
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
	"stat": "OK",
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 2
	}
}`

func TestGetUserGroups(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getGroupsResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const getGroupsPage1Response = `{
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
	"stat": "OK",
	"metadata": {
		"prev_offset": null,
		"next_offset": 2,
		"total_objects": 4
	}
}`

const getGroupsPage2Response = `{
	"response": [{
		"desc": "This is group C",
		"group_id": "DGXXXXXXXXXXXXXXXXXC",
		"name": "Group C",
		"push_enabled": true,
		"sms_enabled": true,
		"status": "active",
		"voice_enabled": true,
		"mobile_otp_enabled": true
	},
	{
		"desc": "This is group D",
		"group_id": "DGXXXXXXXXXXXXXXXXXD",
		"name": "Group D",
		"push_enabled": true,
		"sms_enabled": true,
		"status": "active",
		"voice_enabled": true,
		"mobile_otp_enabled": true
	}],
	"stat": "OK",
	"metadata": {
		"prev_offset": 0,
		"next_offset": null,
		"total_objects": 4
	}
}`

func TestGetUserGroupsMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getGroupsPage1Response)
			} else {
				fmt.Fprintln(w, getGroupsPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserGroups("DU3RP9I2WOC59VZX672N")

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 4 {
		t.Errorf("Expected four groups in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetUserGroupsPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetUserGroups("DU3RP9I2WOC59VZX672N", func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const associateGroupWithUserResponse = `{
	"stat": "OK",
	"response": ""
}`

func TestAssociateGroupWithUser(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, associateGroupWithUserResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.AssociateGroupWithUser("DU3RP9I2WOC59VZX672N", "DGXXXXXXXXXXXXXXXXXX")
	if err != nil {
		t.Errorf("Unexpected error from AssociateGroupWithUser call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
}

const disassociateGroupFromUserResponse = `{
	"stat": "OK",
	"response": ""
}`

func TestDisassociateGroupFromUser(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, associateGroupWithUserResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.DisassociateGroupFromUser("DU3RP9I2WOC59VZX672N", "DGXXXXXXXXXXXXXXXXXX")
	if err != nil {
		t.Errorf("Unexpected error from DisassociateGroupFromUser call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
}

const getUserPhonesResponse = `{
	"stat": "OK",
	"response": [{
		"activated": false,
		"last_seen": "2019-03-04T15:04:04",
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
		"model": "Apple iPhone",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Mobile"
	},
	{
		"activated": false,
		"last_seen": "2019-03-04T15:04:04",
		"capabilities": [
			"phone"
		],
		"extension": "",
		"name": "",
		"number": "+15035550103",
		"phone_id": "DPFZRS9FB0D46QFTM891",
		"platform": "Unknown",
		"model": "Unknown",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Landline"
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 2
	}
}`

func TestGetUserPhones(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUserPhonesResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const getUserPhonesPage1Response = `{
	"stat": "OK",
	"response": [{
		"activated": false,
		"last_seen": "2019-03-04T15:04:04",
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
		"model": "Apple iPhone",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Mobile"
	},
	{
		"activated": false,
		"last_seen": "2019-03-04T15:04:04",
		"capabilities": [
			"phone"
		],
		"extension": "",
		"name": "",
		"number": "+15035550103",
		"phone_id": "DPFZRS9FB0D46QFTM891",
		"platform": "Unknown",
		"model": "Unknown",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Landline"
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": 2,
		"total_objects": 4
	}
}`

const getUserPhonesPage2Response = `{
	"stat": "OK",
	"response": [{
		"activated": false,
		"last_seen": "2019-03-04T15:04:04",
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
		"model": "Apple iPhone",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Mobile"
	},
	{
		"activated": false,
		"last_seen": "2019-03-04T15:04:04",
		"capabilities": [
			"phone"
		],
		"extension": "",
		"name": "",
		"number": "+15035550103",
		"phone_id": "DPFZRS9FB0D46QFTM891",
		"platform": "Unknown",
		"model": "Unknown",
		"postdelay": null,
		"predelay": null,
		"sms_passcodes_sent": false,
		"type": "Landline"
	}],
	"metadata": {
		"prev_offset": 0,
		"next_offset": null,
		"total_objects": 4
	}
}`

func TestGetUserPhonesMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getUserPhonesPage1Response)
			} else {
				fmt.Fprintln(w, getUserPhonesPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserPhones("DU3RP9I2WOC59VZX672N")

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 4 {
		t.Errorf("Expected four phones in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetUserPhonesPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetUserPhones("DU3RP9I2WOC59VZX672N", func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 2
	}
}`

func TestGetUserTokens(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUserTokensResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const getUserTokensPage1Response = `{
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": 2,
		"total_objects": 4
	}
}`

const getUserTokensPage2Response = `{
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
	}],
	"metadata": {
		"prev_offset": 0,
		"next_offset": null,
		"total_objects": 4
	}
}`

func TestGetUserTokensMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getUserTokensPage1Response)
			} else {
				fmt.Fprintln(w, getUserTokensPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserTokens("DU3RP9I2WOC59VZX672N")

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 4 {
		t.Errorf("Expected four tokens in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetUserTokensPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetUserTokens("DU3RP9I2WOC59VZX672N", func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 1
	}
}`

func TestGetUserU2FTokens(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getUserU2FTokensResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const getUserU2FTokensPage1Response = `{
	"stat": "OK",
	"response": [{
		"date_added": 1444678994,
		"registration_id": "D21RU6X1B1DF5P54B6PV"
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": 1,
		"total_objects": 2
	}
}`

const getUserU2FTokensPage2Response = `{
	"stat": "OK",
	"response": [{
		"date_added": 1444678994,
		"registration_id": "D21RU6X1B1DF5P54B6PV"
	}],
	"metadata": {
		"prev_offset": 0,
		"next_offset": null,
		"total_objects": 2
	}
}`

func TestGetUserU2FTokensMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getUserU2FTokensPage1Response)
			} else {
				fmt.Fprintln(w, getUserU2FTokensPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserU2FTokens("DU3RP9I2WOC59VZX672N")

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 2 {
		t.Errorf("Expected two tokens in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetUserU2FTokensPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetUserU2FTokens("DU3RP9I2WOC59VZX672N", func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

func TestGetGroups(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getGroupsResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

func TestGetGroupsMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getGroupsPage1Response)
			} else {
				fmt.Fprintln(w, getGroupsPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetGroups()

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 4 {
		t.Errorf("Expected four groups in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetGroupsPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetGroups(func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
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
		"last_seen": "2019-03-04T15:04:04",
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
		"model": "Google Pixel",
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 1
	}
}`

func TestGetPhones(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getPhonesResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const getPhonesPage1Response = `{
	"stat": "OK",
	"response": [{
		"activated": true,
		"last_seen": "2019-03-04T15:04:04",
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
		"model": "Google Pixel",
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": 1,
		"total_objects": 2
	}
}`

const getPhonesPage2Response = `{
	"stat": "OK",
	"response": [{
		"activated": true,
		"last_seen": "2019-03-04T15:04:04",
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
		"model": "Google Pixel",
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
	}],
	"metadata": {
		"prev_offset": 0,
		"next_offset": null,
		"total_objects": 2
	}
}`

func TestGetPhonesMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getPhonesPage1Response)
			} else {
				fmt.Fprintln(w, getPhonesPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetPhones()

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 2 {
		t.Errorf("Expected two phones in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetPhonesPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetPhones(func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
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
		"model": "Apple iPhone",
		"activated": false,
		"last_seen": "2019-03-04T15:04:04",
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

const deletePhoneResponse = `{
	"stat": "OK",
	"response": ""
}`

func TestDeletePhone(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, deletePhoneResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.DeletePhone("DPFZRS9FB0D46QFTM899")
	if err != nil {
		t.Errorf("Unexpected error from DeletePhone call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 1
	}
}`

func TestGetTokens(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getTokensResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const getTokensPage1Response = `{
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": 1,
		"total_objects": 2
	}
}`

const getTokensPage2Response = `{
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
	}],
	"metadata": {
		"prev_offset": 0,
		"next_offset": null,
		"total_objects": 2
	}
}`

func TestGetTokensMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getTokensPage1Response)
			} else {
				fmt.Fprintln(w, getTokensPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetTokens()

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 2 {
		t.Errorf("Expected two tokens in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetTokensPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetTokens(func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": null,
		"total_objects": 1
	}
}`

func TestGetU2FTokens(t *testing.T) {
	var last_request *http.Request
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getU2FTokensResponse)
			last_request = r
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

	request_query := last_request.URL.Query()
	if request_query["limit"][0] != "100" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "0" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
	}
}

const getU2FTokensPage1Response = `{
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
	}],
	"metadata": {
		"prev_offset": null,
		"next_offset": 1,
		"total_objects": 2
	}
}`

const getU2FTokensPage2Response = `{
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
	}],
	"metadata": {
		"prev_offset": 0,
		"next_offset": null,
		"total_objects": 2
	}
}`

func TestGetU2fTokensMultiple(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requests) == 0 {
				fmt.Fprintln(w, getU2FTokensPage1Response)
			} else {
				fmt.Fprintln(w, getU2FTokensPage2Response)
			}
			requests = append(requests, r)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetU2FTokens()

	if len(requests) != 2 {
		t.Errorf("Expected two requets, found %d", len(requests))
	}

	if len(result.Response) != 2 {
		t.Errorf("Expected two tokens in the response, found %d", len(result.Response))
	}

	if err != nil {
		t.Errorf("Expected err to be nil, found %s", err)
	}
}

func TestGetU2FTokensPageArgs(t *testing.T) {
	requests := []*http.Request{}
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getEmptyPageArgsResponse)
			requests = append(requests, r)
		}),
	)

	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	_, err := duo.GetU2FTokens(func(values *url.Values) {
		values.Set("limit", "200")
		values.Set("offset", "1")
		return
	})

	if err != nil {
		t.Errorf("Encountered unexpected error: %s", err)
	}

	if len(requests) != 1 {
		t.Errorf("Expected there to be one request, found %d", len(requests))
	}
	request := requests[0]
	request_query := request.URL.Query()
	if request_query["limit"][0] != "200" {
		t.Errorf("Expected to see a limit of 100 in request, bug got %s", request_query["limit"])
	}
	if request_query["offset"][0] != "1" {
		t.Errorf("Expected to see an offset of 0 in request, bug got %s", request_query["offset"])
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

const getBypassCodesResponse = `{
	"stat": "OK",
	"response": [
		"407176182",
		"016931781",
		"338390347",
		"537828175",
		"006165274",
		"438680449",
		"877647224",
		"196167433",
		"719424708",
		"727559878"
	]
}`

func TestGetBypassCodes(t *testing.T) {
	ts := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, getBypassCodesResponse)
		}),
	)
	defer ts.Close()

	duo := buildAdminClient(ts.URL, nil)

	result, err := duo.GetUserBypassCodes("D21RU6X1B1DF5P54B6PV")

	if err != nil {
		t.Errorf("Unexpected error from GetUserBypassCodes call %v", err.Error())
	}
	if result.Stat != "OK" {
		t.Errorf("Expected OK, but got %s", result.Stat)
	}
	if len(result.Response) != 10 {
		t.Errorf("Expected 10 codes, but got %d", len(result.Response))
	}
}
