package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/GridPlus/phonon-client/model"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/card"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/permission"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/web/interfaces"
	"github.com/stretchr/testify/assert"
)

var web *WebServer
var client http.Client

type TestHelpers[body any] struct {
	Teardown       func(t *testing.T)
	AppId          string
	AddPermissions func(permissions []string)
	SetAsAdmin     func()
	SendRequest    func(method string, endpoint string, body *body) *http.Response
}

func setupTest[body any](t *testing.T) TestHelpers[body] {
	filePath := "./permissions.json"

	ioutil.WriteFile(filePath, []byte("[]"), 0644)

	if web == nil {
		cardManager := card.NewCardManager()
		web, _ = New(cardManager, CreateSecret(), filePath)
		go web.Start(":3001")
	}

	getIdReq, _ := http.NewRequest("GET", "http://localhost:3001/permissions", nil)
	getIdRes, _ := client.Do(getIdReq)
	appId, _ := getAuthId(getIdRes)

	return TestHelpers[body]{
		Teardown: func(t *testing.T) {
			os.Remove(filePath)
			web.adminSessionId = ""
			web.cards.ClearMockCards()
		},
		AppId:          appId,
		AddPermissions: func(permissions []string) { web.permissions.AddPermissions(appId, permissions) },
		SetAsAdmin:     func() { web.adminSessionId = appId },
		SendRequest: func(method string, endpoint string, body *body) *http.Response {

			requestBodyJson, _ := json.Marshal(body)
			bodyReader := bytes.NewReader(requestBodyJson)

			req, _ := http.NewRequest(method, endpoint, bodyReader)
			req.AddCookie(getIdRes.Cookies()[0])

			res, _ := client.Do(req)
			return res
		},
	}
}

func createMockCard(initalise bool, unlock bool) *card.Card {
	cardId, _ := web.cards.CreateMockCard(initalise)

	card := web.cards.GetCard(cardId)

	if unlock {
		card.Session.VerifyPIN("111111")
	}

	return card
}

func getAuthId(r *http.Response) (string, error) {
	for _, cookie := range r.Cookies() {
		if cookie.Name == TOKEN_COOKIE_NAME {
			idAndSignature := strings.Split(cookie.Value, ":")
			return idAndSignature[0], nil

		}
	}
	return "", errors.New("auth token not found")
}

func TestGetPermissions(t *testing.T) {
	ENDPOINT := "http://localhost:3001/permissions"

	t.Run("Returns an empty array when app has no permissions", func(t *testing.T) {
		helpers := setupTest[any](t)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", ENDPOINT, nil)

		var body interfaces.GetPermissionsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Empty(body.Permissions)
	})

	t.Run("Returns the expected app permissions", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_CREATE_PHONONS})
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", ENDPOINT, nil)

		var body interfaces.GetPermissionsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Contains(body.Permissions, permission.PERMISSION_CREATE_PHONONS)
		assert.Len(body.Permissions, 1)
	})
}

func TestRequestPermissions(t *testing.T) {
	ENDPOINT := "http://localhost:3001/permissions"

	t.Run("Returns bad request when unknown permission are requested", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestPermissionsRequestBody](t)
		defer helpers.Teardown(t)

		requestBody := interfaces.RequestPermissionsRequestBody{
			Permissions: []string{"unknown_permission"},
		}

		res := helpers.SendRequest("POST", ENDPOINT, &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusBadRequest, res.StatusCode)
	})

	t.Run("Returns forbidden when invalid admin code supplied", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestPermissionsRequestBody](t)
		defer helpers.Teardown(t)

		var adminToken string = web.AdminToken + "dfads"

		requestBody := interfaces.RequestPermissionsRequestBody{
			Permissions: []string{},
			AdminToken:  &adminToken,
		}

		res := helpers.SendRequest("POST", ENDPOINT, &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns ok when valid permissions are requested", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestPermissionsRequestBody](t)
		defer helpers.Teardown(t)

		requestBody := interfaces.RequestPermissionsRequestBody{
			Permissions: []string{permission.PERMISSION_CREATE_PHONONS, permission.PERMISSION_READ_CARDS},
		}

		res := helpers.SendRequest("POST", ENDPOINT, &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
	})

	t.Run("Returns ok and sets admin when valid admin code suplied", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestPermissionsRequestBody](t)
		defer helpers.Teardown(t)

		requestBody := interfaces.RequestPermissionsRequestBody{
			Permissions: []string{},
			AdminToken:  &web.AdminToken,
		}

		res := helpers.SendRequest("POST", ENDPOINT, &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Equal(helpers.AppId, web.adminSessionId)
	})

}

func TestAdminAddPermissions(t *testing.T) {
	ENDPOINT := "http://localhost:3001/admin/permissions"
	APP_ID := "abc123"

	t.Run("Returns bad request when unknown permission are requested", func(t *testing.T) {
		helpers := setupTest[interfaces.AddPermissionsRequestBody](t)
		helpers.SetAsAdmin()
		defer helpers.Teardown(t)

		requestBody := interfaces.AddPermissionsRequestBody{
			AppId:       APP_ID,
			Permissions: []string{"unknown_permission"},
		}

		res := helpers.SendRequest("POST", ENDPOINT, &requestBody)

		permissions := web.permissions.GetPermissions(APP_ID)

		assert := assert.New(t)
		assert.Equal(http.StatusBadRequest, res.StatusCode)
		assert.Empty(permissions)
	})

	t.Run("Returns forbidden when not an admin", func(t *testing.T) {
		helpers := setupTest[interfaces.AddPermissionsRequestBody](t)
		defer helpers.Teardown(t)

		requestBody := interfaces.AddPermissionsRequestBody{
			AppId:       APP_ID,
			Permissions: []string{permission.PERMISSION_CREATE_PHONONS},
		}

		res := helpers.SendRequest("POST", ENDPOINT, &requestBody)

		permissions := web.permissions.GetPermissions(APP_ID)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
		assert.Empty(permissions)

	})

	t.Run("Correctly set permissions", func(t *testing.T) {
		helpers := setupTest[interfaces.AddPermissionsRequestBody](t)
		helpers.SetAsAdmin()
		defer helpers.Teardown(t)

		requestBody := interfaces.AddPermissionsRequestBody{
			AppId:       APP_ID,
			Permissions: []string{permission.PERMISSION_CREATE_PHONONS},
		}

		res := helpers.SendRequest("POST", ENDPOINT, &requestBody)

		permissions := web.permissions.GetPermissions(APP_ID)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Contains(permissions, permission.PERMISSION_CREATE_PHONONS)
	})
}

func TestListCards(t *testing.T) {
	ENDPOINT := "http://localhost:3001/cards"

	t.Run("Returns forbidden when app doesnt have correct permissions", func(t *testing.T) {
		helpers := setupTest[any](t)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", ENDPOINT, nil)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns an empty array when no cards are connected", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_CARDS})
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", ENDPOINT, nil)

		var body interfaces.GetCardsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Empty(body.Cards)
	})

	t.Run("Returns the correct number of cards when app has permission", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_CARDS})
		createMockCard(true, false)
		createMockCard(true, false)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", ENDPOINT, nil)

		var body interfaces.GetCardsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Len(body.Cards, 2)
	})

	t.Run("Returns the correct number of cards when app is admin", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.SetAsAdmin()
		createMockCard(true, false)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", ENDPOINT, nil)

		var body interfaces.GetCardsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Len(body.Cards, 1)
	})
}

func TestRequestUnlockCard(t *testing.T) {
	getEndpoint := func(cardId string) string {
		return "http://localhost:3001/cards/" + cardId + "/unlock"
	}

	t.Run("Returns forbidden when app doesnt have correct permissions", func(t *testing.T) {
		helpers := setupTest[any](t)
		card := createMockCard(true, false)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid card ID", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_CARDS})
		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint("invalid"), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Returns success when app has permission", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_CARDS})
		card := createMockCard(true, false)

		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
	})
}

func TestRequestRedeem(t *testing.T) {
	getEndpoint := func(cardId string) string {
		return "http://localhost:3001/cards/" + cardId + "/phonons"
	}

	t.Run("Returns forbidden when app doesnt have correct permissions", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestRedeemPhononRequestBody](t)
		card := createMockCard(true, true)
		index, _, _ := card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RequestRedeemPhononRequestBody{
			Index: uint16(index),
		}

		res := helpers.SendRequest("DELETE", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns forbidden when card is locked", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestRedeemPhononRequestBody](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_PHONONS})
		card := createMockCard(true, false)
		index, _, _ := card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RequestRedeemPhononRequestBody{
			Index: uint16(index),
		}

		res := helpers.SendRequest("DELETE", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid card ID", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestRedeemPhononRequestBody](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_PHONONS})
		card := createMockCard(true, true)
		index, _, _ := card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RequestRedeemPhononRequestBody{
			Index: uint16(index),
		}

		res := helpers.SendRequest("DELETE", getEndpoint("invalid"), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Returns success when app has permission", func(t *testing.T) {
		helpers := setupTest[interfaces.RequestRedeemPhononRequestBody](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_PHONONS})
		card := createMockCard(true, true)
		index, _, _ := card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RequestRedeemPhononRequestBody{
			Index: uint16(index),
		}

		res := helpers.SendRequest("DELETE", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
	})
}

func TestSetCardName(t *testing.T) {
	getEndpoint := func(cardId string) string {
		return "http://localhost:3001/cards/" + cardId + "/name"
	}

	NEW_NAME := "new_name"

	t.Run("Returns forbidden when app doesnt have correct permissions", func(t *testing.T) {
		helpers := setupTest[interfaces.SetCardNameRequestBody](t)
		card := createMockCard(true, true)

		defer helpers.Teardown(t)

		requestBody := interfaces.SetCardNameRequestBody{
			Name: NEW_NAME,
		}

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid card ID", func(t *testing.T) {
		helpers := setupTest[interfaces.SetCardNameRequestBody](t)
		helpers.AddPermissions([]string{permission.PERMISSION_SET_CARD_NAME})
		defer helpers.Teardown(t)

		requestBody := interfaces.SetCardNameRequestBody{
			Name: NEW_NAME,
		}

		res := helpers.SendRequest("POST", getEndpoint("invalid"), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Returns forbidden when card is locked", func(t *testing.T) {
		helpers := setupTest[interfaces.SetCardNameRequestBody](t)
		helpers.AddPermissions([]string{permission.PERMISSION_SET_CARD_NAME})
		card := createMockCard(true, false)

		defer helpers.Teardown(t)

		requestBody := interfaces.SetCardNameRequestBody{
			Name: NEW_NAME,
		}

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Correctly sets card name when app has permission", func(t *testing.T) {
		helpers := setupTest[interfaces.SetCardNameRequestBody](t)
		helpers.AddPermissions([]string{permission.PERMISSION_SET_CARD_NAME})
		card := createMockCard(true, true)
		defer helpers.Teardown(t)

		requestBody := interfaces.SetCardNameRequestBody{
			Name: NEW_NAME,
		}

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), &requestBody)

		cardName, _ := card.Session.GetName()

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Equal(cardName, NEW_NAME)
	})

	t.Run("Correctly sets card name when app is admin", func(t *testing.T) {
		helpers := setupTest[interfaces.SetCardNameRequestBody](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, true)
		defer helpers.Teardown(t)

		requestBody := interfaces.SetCardNameRequestBody{
			Name: NEW_NAME,
		}

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), &requestBody)

		cardName, _ := card.Session.GetName()

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Equal(cardName, NEW_NAME)
	})
}

func TestListPhonons(t *testing.T) {
	getEndpoint := func(cardId string) string {
		return "http://localhost:3001/cards/" + cardId + "/phonons"
	}

	t.Run("Returns forbidden when app doesnt have correct permissions", func(t *testing.T) {
		helpers := setupTest[any](t)
		card := createMockCard(true, true)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", getEndpoint(card.Session.GetCardId()), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns forbidden when card is locked", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_PHONONS})
		card := createMockCard(true, false)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", getEndpoint(card.Session.GetCardId()), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid card ID", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_PHONONS})
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", getEndpoint("invalid"), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Returns an empty array when no phonons exist", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_PHONONS})
		card := createMockCard(true, true)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", getEndpoint(card.Session.GetCardId()), nil)

		var body interfaces.GetPhononsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Empty(body.Phonons)
	})

	t.Run("Returns the expected number of phonons when app has permission", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_READ_PHONONS})
		card := createMockCard(true, true)
		card.Session.CreatePhonon()
		card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", getEndpoint(card.Session.GetCardId()), nil)

		var body interfaces.GetPhononsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Len(body.Phonons, 2)
	})

	t.Run("Returns the expected number of phonons when app is admin", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, true)
		card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		res := helpers.SendRequest("GET", getEndpoint(card.Session.GetCardId()), nil)

		var body interfaces.GetPhononsResponseBody
		json.NewDecoder(res.Body).Decode(&body)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Len(body.Phonons, 1)
	})
}

func TestCreatePhonon(t *testing.T) {
	getEndpoint := func(cardId string) string {
		return "http://localhost:3001/cards/" + cardId + "/phonons"
	}

	t.Run("Returns forbidden when app doesnt have correct permissions", func(t *testing.T) {
		helpers := setupTest[any](t)
		card := createMockCard(true, true)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns forbidden when card is locked", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_CREATE_PHONONS})
		card := createMockCard(true, false)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid card ID", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_CREATE_PHONONS})
		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint("invalid"), nil)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Creates a phonon when app has permission", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.AddPermissions([]string{permission.PERMISSION_CREATE_PHONONS})
		card := createMockCard(true, true)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), nil)

		phonons, _ := card.Session.ListPhonons(model.CurrencyType(0), 0, 0)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Len(phonons, 1)
	})

	t.Run("Creates a phonon when app is admin", func(t *testing.T) {
		helpers := setupTest[any](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, true)
		defer helpers.Teardown(t)

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), nil)

		phonons, _ := card.Session.ListPhonons(model.CurrencyType(0), 0, 0)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Len(phonons, 1)
	})
}

func TestRedeemPhonon(t *testing.T) {
	getEndpoint := func(cardId string) string {
		return "http://localhost:3001/admin/cards/" + cardId + "/phonons"
	}

	t.Run("Returns forbidden when app is not admin", func(t *testing.T) {
		helpers := setupTest[interfaces.RedeemPhononRequestBody](t)
		card := createMockCard(true, true)
		index, _, _ := card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RedeemPhononRequestBody{
			Index: uint16(index),
		}

		res := helpers.SendRequest("DELETE", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns forbidden when card is locked", func(t *testing.T) {
		helpers := setupTest[interfaces.RedeemPhononRequestBody](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, false)
		index, _, _ := card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RedeemPhononRequestBody{
			Index: uint16(index),
		}

		res := helpers.SendRequest("DELETE", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid card ID", func(t *testing.T) {
		helpers := setupTest[interfaces.RedeemPhononRequestBody](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, true)
		card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RedeemPhononRequestBody{
			Index: 0,
		}

		res := helpers.SendRequest("DELETE", getEndpoint("invalid"), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid phonon index", func(t *testing.T) {
		helpers := setupTest[interfaces.RedeemPhononRequestBody](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, true)
		card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RedeemPhononRequestBody{
			Index: 1,
		}

		res := helpers.SendRequest("DELETE", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Redeems phonon when app is admin", func(t *testing.T) {
		helpers := setupTest[interfaces.RedeemPhononRequestBody](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, true)
		index, _, _ := card.Session.CreatePhonon()
		defer helpers.Teardown(t)

		requestBody := interfaces.RedeemPhononRequestBody{
			Index: uint16(index),
		}

		res := helpers.SendRequest("DELETE", getEndpoint(card.Session.GetCardId()), &requestBody)

		phonons, _ := card.Session.ListPhonons(model.CurrencyType(0), 0, 0)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.Len(phonons, 0)
	})
}

func TestInitialiseCard(t *testing.T) {
	getEndpoint := func(cardId string) string {
		return "http://localhost:3001/admin/cards/" + cardId + "/init"
	}

	t.Run("Returns forbidden when app is not admin", func(t *testing.T) {
		helpers := setupTest[interfaces.InitialiseCardRequestBody](t)
		card := createMockCard(false, false)
		defer helpers.Teardown(t)

		requestBody := interfaces.InitialiseCardRequestBody{
			Pin: "111111",
		}

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusForbidden, res.StatusCode)
	})

	t.Run("Returns not found when supplied an invalid card ID", func(t *testing.T) {
		helpers := setupTest[interfaces.InitialiseCardRequestBody](t)
		helpers.SetAsAdmin()
		defer helpers.Teardown(t)

		requestBody := interfaces.InitialiseCardRequestBody{
			Pin: "111111",
		}

		res := helpers.SendRequest("POST", getEndpoint("invalid"), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusNotFound, res.StatusCode)
	})

	t.Run("Returns bad request when card is initalised", func(t *testing.T) {
		helpers := setupTest[interfaces.InitialiseCardRequestBody](t)
		helpers.SetAsAdmin()
		card := createMockCard(true, false)
		defer helpers.Teardown(t)

		requestBody := interfaces.InitialiseCardRequestBody{
			Pin: "111111",
		}

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusBadRequest, res.StatusCode)
	})

	t.Run("Initialises the card when app is admin", func(t *testing.T) {
		helpers := setupTest[interfaces.InitialiseCardRequestBody](t)
		helpers.SetAsAdmin()
		card := createMockCard(false, false)
		defer helpers.Teardown(t)

		requestBody := interfaces.InitialiseCardRequestBody{
			Pin: "111111",
		}

		res := helpers.SendRequest("POST", getEndpoint(card.Session.GetCardId()), &requestBody)

		assert := assert.New(t)
		assert.Equal(http.StatusOK, res.StatusCode)
		assert.True(card.Session.IsInitialized())
	})
}
