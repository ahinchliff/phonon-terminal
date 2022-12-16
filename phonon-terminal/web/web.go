package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/GridPlus/phonon-client/model"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/card"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/permission"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/web/interfaces"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
)

type ContextKey int

const (
	TOKEN_COOKIE_NAME             = "auth_token"
	CONTEXT_APP_ID_KEY ContextKey = 1
)

type WebServer struct {
	cards          *card.CardManager
	permissions    *permission.PermissionManager
	sockets        map[string]*websocket.Conn
	secret         *ecdsa.PrivateKey
	adminSessionId string
	AdminToken     string
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func New(cm *card.CardManager, secret string, permissionStoreFilePath string) (*WebServer, error) {
	adminKey := uuid.NewString()

	signatureData := crypto.Keccak256([]byte(adminKey))

	privateKey, err := crypto.HexToECDSA(secret)
	if err != nil {
		return nil, err
	}

	adminToken, err := ecdsa.SignASN1(rand.Reader, privateKey, signatureData)
	if err != nil {
		return nil, err
	}

	pm := permission.NewPermissionsManager(permissionStoreFilePath)

	return &WebServer{
		cards:       cm,
		permissions: pm,
		sockets:     make(map[string]*websocket.Conn),
		secret:      privateKey,
		AdminToken:  hex.EncodeToString(adminToken),
	}, nil
}

func (web *WebServer) Start(addr string) error {
	r := mux.NewRouter()
	r.Use(contentTypeApplicationJsonMiddleware)
	r.Use(web.getAuthMiddleware())

	r.HandleFunc("/ws", web.establishWSConnection).Methods("GET")

	r.HandleFunc("/permissions", handlerWrapper(web, RouteSettings{}, listPermissions)).Methods("GET")
	r.HandleFunc("/permissions", handlerWrapper(web, RouteSettings{}, requestPermissions)).Methods("POST")

	r.HandleFunc("/cards", handlerWrapper(web, listCardsSettings, listCards)).Methods("GET")
	r.HandleFunc("/cards/{cardId}/unlock", handlerWrapper(web, requestCardUnlockSettings, requestUnlockCard)).Methods("POST")
	r.HandleFunc("/cards/{cardId}/name", handlerWrapper(web, setCardNameSetting, setCardName)).Methods("POST")
	r.HandleFunc("/cards/{cardId}/phonons", handlerWrapper(web, listPhononsSettings, listPhonons)).Methods("GET")
	r.HandleFunc("/cards/{cardId}/phonons", handlerWrapper(web, createPhononSettings, createPhonon)).Methods("POST")
	r.HandleFunc("/cards/{cardId}/phonons", handlerWrapper(web, requestRedeemPhononSettings, requestRedeemPhonon)).Methods("DELETE")

	r.HandleFunc("/admin/permissions", handlerWrapper(web, adminAddPermissionsSettings, adminAddPermissions)).Methods("POST")
	r.HandleFunc("/admin/cards/{cardId}/init", handlerWrapper(web, adminInitialiseCardSettings, adminInitialiseCard)).Methods("POST")
	r.HandleFunc("/admin/cards/{cardId}/unlock", handlerWrapper(web, adminUnlockCardSettings, adminUnlockCard)).Methods("POST")
	r.HandleFunc("/admin/cards/{cardId}/phonons", handlerWrapper(web, adminRedeemPhononSettings, adminRedeemPhonon)).Methods("DELETE")
	r.HandleFunc("/admin/cards/{cardId}/phonons/send", handlerWrapper(web, adminSendPhononSettings, adminSendPhonon)).Methods("POST")
	r.HandleFunc("/admin/cards/{cardId}/remote", handlerWrapper(web, adminConnectToRemotePairingServerSettings, adminConnectToRemotePairingServer)).Methods("POST")
	r.HandleFunc("/admin/cards/{cardId}/pair", handlerWrapper(web, adminPairCardSettings, adminPairCard)).Methods("POST")

	c := cors.New(cors.Options{
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete},
		AllowCredentials: true,
		AllowOriginFunc:  func(origin string) bool { return true },
	})

	go func() {
		for {
			select {
			case cardId := <-web.cards.NewCardChannel:
				sendCardEvent(interfaces.SOCKET_EVENT_CARD_INSERTED, web, cardId)
			case cardId := <-web.cards.RemovedCardChannel:
				sendCardEvent(interfaces.SOCKET_EVENT_CARD_REMOVED, web, cardId)
			}
		}
	}()

	handler := c.Handler(r)
	err := http.ListenAndServe(addr, handler)

	if err != nil {
		fmt.Println(err.Error())
	}

	return err
}

type HandlerPayload struct {
	Web   *WebServer
	AppId string
	Card  *card.Card
	Body  io.ReadCloser
}

type HandlerError struct {
	Code    int
	Message string
}

func handlerWrapper[t any](web *WebServer, requirements RouteSettings, handler func(payload HandlerPayload) (*t, *HandlerError)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		appId, card, err := web.checkRouteSettings(w, r, requirements)
		if err != nil {
			return
		}
		result, error := handler(HandlerPayload{
			Web:   web,
			AppId: appId,
			Card:  card,
			Body:  r.Body,
		})

		if error != nil {
			http.Error(w, error.Message, error.Code)
			return
		}

		json.NewEncoder(w).Encode(result)
	}
}

func newHandlerError(code int, message string) *HandlerError {
	return &HandlerError{
		Code:    code,
		Message: message,
	}

}

func (web *WebServer) establishWSConnection(w http.ResponseWriter, r *http.Request) {
	appId := getAppIdFromRequest(r)

	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	web.sockets[appId] = ws

	json.NewEncoder(w).Encode(interfaces.SuccessResponse{
		Success: true,
	})
}

func listPermissions(p HandlerPayload) (*interfaces.GetPermissionsResponseBody, *HandlerError) {
	permissions := p.Web.permissions.GetPermissions(p.AppId)
	// golang likes to encode empty arrays as nil. This hack ensures the correct JSON is returned.
	if len(permissions) == 0 {
		permissions = make([]string, 0)
	}

	return &interfaces.GetPermissionsResponseBody{
		Permissions: permissions,
	}, nil
}

func requestPermissions(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	var body interfaces.RequestPermissionsRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	areValid, invalid := permission.ArePermissionsValid(body.Permissions)
	if !areValid {
		return nil, newHandlerError(http.StatusBadRequest, "invalid permissions: "+strings.Join(invalid, ","))
	}

	newPermissions := p.Web.permissions.GetNewPermissions(p.AppId, body.Permissions)

	if body.AdminToken != nil {
		if *body.AdminToken != p.Web.AdminToken {
			return nil, newHandlerError(http.StatusForbidden, "invalid admin token")
		}
		p.Web.adminSessionId = p.AppId
	} else {
		payload := interfaces.NewPermissionRequestEvent(p.AppId, newPermissions)
		sendEvent(p.Web.adminSessionId, payload, p.Web)
	}

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var listCardsSettings = RouteSettings{
	RequiredPermission: &permission.PERMISSION_READ_CARDS,
}

func listCards(p HandlerPayload) (*interfaces.GetCardsResponseBody, *HandlerError) {
	cards := interfaces.CardsToHttpCards(p.Web.cards.Cards)
	// golang likes to encode empty arrays as nil. This hack ensures the correct JSON is returned.
	if len(cards) == 0 {
		cards = make([]interfaces.Card, 0)
	}
	return &interfaces.GetCardsResponseBody{
		Cards: cards,
	}, nil
}

var requestCardUnlockSettings = RouteSettings{
	RequiredPermission: &permission.PERMISSION_READ_CARDS,
	CardCanBeLocked:    true,
}

func requestUnlockCard(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	if !p.Card.Session.IsUnlocked() {
		payload := interfaces.NewCardUnlockRequestEvent(p.AppId, p.Card.Session.GetCardId())
		sendEvent(p.Web.adminSessionId, payload, p.Web)
	}

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var setCardNameSetting = RouteSettings{
	RequiredPermission: &permission.PERMISSION_SET_CARD_NAME,
}

func setCardName(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	var body interfaces.SetCardNameRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	err = p.Card.Session.SetName(body.Name)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var listPhononsSettings = RouteSettings{
	RequiredPermission: &permission.PERMISSION_READ_PHONONS,
}

func listPhonons(p HandlerPayload) (*interfaces.GetPhononsResponseBody, *HandlerError) {
	phonons, err := p.Card.Session.ListPhonons(0, 0, 0)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	for _, ph := range phonons {
		if ph.PubKey == nil {
			ph.PubKey, err = p.Card.Session.GetPhononPubKey(ph.KeyIndex, ph.CurveType)
			return nil, newHandlerError(http.StatusInternalServerError, err.Error())
		}
	}

	httpPhonons := interfaces.PhononsToHttpPhonons(phonons)

	return &interfaces.GetPhononsResponseBody{
		Phonons: httpPhonons,
	}, nil
}

var createPhononSettings = RouteSettings{
	RequiredPermission: &permission.PERMISSION_CREATE_PHONONS,
}

func createPhonon(p HandlerPayload) (*interfaces.Phonon, *HandlerError) {
	index, publicKey, err := p.Card.Session.CreatePhonon()
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	sendPhononEvent(interfaces.SOCKET_EVENT_PHONON_CREATED, p.Web, p.Card.Session.GetCardId(), uint16(index))

	return &interfaces.Phonon{
		Index:     uint16(index),
		PublicKey: publicKey.String(),
	}, nil
}

var requestRedeemPhononSettings = RouteSettings{
	RequiredPermission: &permission.PERMISSION_READ_PHONONS,
}

func requestRedeemPhonon(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	var body interfaces.RequestRedeemPhononRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	phonons, err := p.Card.Session.ListPhonons(0, 0, 0)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	foundPhonon := false

	for _, phonon := range phonons {
		if phonon.KeyIndex == model.PhononKeyIndex(body.Index) {
			foundPhonon = true
			break
		}
	}

	if !foundPhonon {
		return nil, newHandlerError(http.StatusNotFound, "phonon not found")
	}

	payload := interfaces.NewRedeemRequestEvent(p.AppId, p.Card.Session.GetCardId(), body.Index)
	sendEvent(p.Web.adminSessionId, payload, p.Web)

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var adminConnectToRemotePairingServerSettings = RouteSettings{
	RequiresAdmin: true,
}

func adminConnectToRemotePairingServer(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	var body interfaces.ConnectToPairingServerRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	err = p.Card.Session.ConnectToRemoteProvider(body.Url)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, err.Error())
	}

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var adminSendPhononSettings = RouteSettings{
	RequiresAdmin: true,
}

func adminSendPhonon(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	var body interfaces.SendPhononsRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	phonons, err := p.Card.Session.ListPhonons(0, 0, 0)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	var indices []model.PhononKeyIndex

	for _, i := range body.PhononIndices {
		indices = append(indices, model.PhononKeyIndex(i))
	}

	notFoundIndices := []model.PhononKeyIndex{}

	for _, i := range indices {
		foundPhonon := false
		for _, phonon := range phonons {
			if phonon.KeyIndex == i {
				foundPhonon = true
				break
			}
		}

		if !foundPhonon {
			notFoundIndices = append(notFoundIndices, i)
		}
	}

	if len(notFoundIndices) > 0 {
		return nil, newHandlerError(http.StatusNotFound, "phonons not found: "+fmt.Sprint(notFoundIndices))
	}

	err = p.Card.Session.SendPhonons(indices)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var adminPairCardSettings = RouteSettings{
	RequiresAdmin: true,
}

func adminPairCard(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	var body interfaces.PairCardRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	err = p.Card.Session.ConnectToCounterparty(body.CounterpartyCardId)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, err.Error())
	}

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var adminRedeemPhononSettings = RouteSettings{
	RequiresAdmin: true,
}

func adminRedeemPhonon(p HandlerPayload) (*interfaces.RedeemPhononResponseBody, *HandlerError) {
	var body interfaces.RedeemPhononRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	phonons, err := p.Card.Session.ListPhonons(0, 0, 0)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	foundPhonon := false

	for _, phonon := range phonons {
		if phonon.KeyIndex == model.PhononKeyIndex(body.Index) {
			foundPhonon = true
			break
		}
	}

	if !foundPhonon {
		return nil, newHandlerError(http.StatusNotFound, "phonon not found")
	}

	privateKey, err := p.Card.Session.DestroyPhonon(model.PhononKeyIndex(body.Index))
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	privateKeyHex := hex.EncodeToString(crypto.FromECDSA(privateKey))

	if body.AppId != nil {
		sendEvent(*body.AppId, interfaces.NewPhononRedeemActionedEvent(p.Card.Session.GetCardId(), body.Index, privateKeyHex), p.Web)
	}

	sendPhononEvent(interfaces.SOCKET_EVENT_PHONON_REDEEMED, p.Web, p.Card.Session.GetCardId(), body.Index)

	return &interfaces.RedeemPhononResponseBody{
		PrivateKey: privateKeyHex,
	}, nil
}

var adminInitialiseCardSettings = RouteSettings{
	RequiresAdmin:          true,
	CardCanBeLocked:        true,
	CardCanBeUninitialised: true,
}

func adminInitialiseCard(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	if p.Card.Session.IsInitialized() {
		return nil, newHandlerError(http.StatusBadRequest, "card is already initialized")
	}

	var body interfaces.InitialiseCardRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	err = p.Card.Session.Init(body.Pin)
	if err != nil {
		return nil, newHandlerError(http.StatusInternalServerError, err.Error())
	}

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var adminUnlockCardSettings = RouteSettings{
	RequiresAdmin:   true,
	CardCanBeLocked: true,
}

func adminUnlockCard(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	if p.Card.Session.IsUnlocked() {
		return &interfaces.SuccessResponse{
			Success: true,
		}, nil
	}

	var body interfaces.UnlockCardRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	err = p.Card.Session.VerifyPIN(body.Pin)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid pin")
	}

	sendCardEvent(interfaces.SOCKET_EVENT_CARD_UNLOCKED, p.Web, p.Card.Session.GetCardId())

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

var adminAddPermissionsSettings = RouteSettings{
	RequiresAdmin: true,
}

func adminAddPermissions(p HandlerPayload) (*interfaces.SuccessResponse, *HandlerError) {
	var body interfaces.AddPermissionsRequestBody

	err := json.NewDecoder(p.Body).Decode(&body)
	if err != nil {
		return nil, newHandlerError(http.StatusBadRequest, "invalid body")
	}

	areValid, invalid := permission.ArePermissionsValid(body.Permissions)

	if !areValid {
		return nil, newHandlerError(http.StatusBadRequest, "invalid permissions: "+strings.Join(invalid, ","))
	}

	p.Web.permissions.AddPermissions(body.AppId, body.Permissions)

	allPermissions := p.Web.permissions.GetPermissions(body.AppId)

	payload := interfaces.NewPermissionsEvent(body.Permissions, allPermissions)

	sendEvent(body.AppId, payload, p.Web)

	return &interfaces.SuccessResponse{
		Success: true,
	}, nil
}

func contentTypeApplicationJsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func getAppIdFromCookie(r *http.Request, secret *ecdsa.PrivateKey) (appId string, err error) {
	cookie, err := r.Cookie(TOKEN_COOKIE_NAME)
	if err != nil {
		return appId, errors.New("cookie not set")
	}

	idAndSignature := strings.Split(cookie.Value, ":")

	if len(idAndSignature) != 2 {
		return appId, errors.New("cookie doesnt have expected data")
	}

	id := idAndSignature[0]
	signatureHex := idAndSignature[1]

	signatureData := crypto.Keccak256([]byte(id))

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return appId, errors.New("failed to decode signature")
	}

	if !ecdsa.VerifyASN1(&secret.PublicKey, signatureData, signature) {
		return appId, errors.New("failed to verify cookie signature")
	}

	return id, nil
}

func getAppIdFromRequest(r *http.Request) string {
	ctx := r.Context()
	appId, _ := ctx.Value(CONTEXT_APP_ID_KEY).(string)
	return appId
}

func sendCardEvent(event string, web *WebServer, cardId string) {
	cards := interfaces.CardsToHttpCards(web.cards.Cards)
	payload := interfaces.NewCardEvent(event, cardId, cards)

	for id := range web.sockets {
		if web.permissions.HasPermission(id, permission.PERMISSION_READ_CARDS) || id == web.adminSessionId {
			sendEvent(id, payload, web)
		}
	}
}

func sendPhononEvent(event string, web *WebServer, cardId string, phononIndex uint16) {
	payload := interfaces.NewPhononEvent(event, cardId, phononIndex)

	for id := range web.sockets {
		if web.permissions.HasPermission(id, permission.PERMISSION_READ_PHONONS) || id == web.adminSessionId {
			sendEvent(id, payload, web)
		}
	}
}

func sendEvent[t any](appId string, event interfaces.SocketEvent[t], web *WebServer) error {
	socket := web.sockets[appId]
	if socket == nil {
		return errors.New("no socket found that id: " + appId)
	}

	json, err := json.Marshal(event)
	if err != nil {
		return err
	}

	fmt.Println("Sending " + event.Event + " to " + appId)
	socket.WriteMessage(1, json)
	return nil
}

func CreateSecret() string {
	secret, _ := crypto.GenerateKey()
	return hex.EncodeToString(crypto.FromECDSA(secret))
}

func (web *WebServer) getAuthMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			appId, err := getAppIdFromCookie(r, web.secret)

			if err != nil {

				newAppId := uuid.NewString()

				signatureData := crypto.Keccak256([]byte(newAppId))

				signature, err := ecdsa.SignASN1(rand.Reader, web.secret, signatureData)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}

				cookie := &http.Cookie{
					Name:     TOKEN_COOKIE_NAME,
					Value:    newAppId + ":" + hex.EncodeToString(signature),
					Expires:  time.Now().AddDate(1, 0, 0),
					SameSite: http.SameSiteStrictMode,
					HttpOnly: true,
					Path:     "/",
				}

				ctx = context.WithValue(ctx, CONTEXT_APP_ID_KEY, newAppId)
				http.SetCookie(w, cookie)
			} else {
				ctx = context.WithValue(ctx, CONTEXT_APP_ID_KEY, appId)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type RouteSettings struct {
	RequiresAdmin          bool
	RequiredPermission     *string
	CardCanBeLocked        bool
	CardCanBeUninitialised bool
}

func (web *WebServer) checkRouteSettings(w http.ResponseWriter, r *http.Request, requirements RouteSettings) (appId string, card *card.Card, err error) {
	appId = getAppIdFromRequest(r)

	if requirements.RequiresAdmin && appId != web.adminSessionId {
		w.WriteHeader(http.StatusForbidden)
		return "", nil, errors.New("App not admin")
	}

	if appId != web.adminSessionId && requirements.RequiredPermission != nil && !web.permissions.HasPermission(appId, *requirements.RequiredPermission) {
		w.WriteHeader(http.StatusForbidden)
		return "", nil, errors.New("App doesn't have permission")
	}

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	if cardId != "" {
		card = web.cards.GetCard(cardId)
	}

	if cardId != "" && card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return "", nil, errors.New("No such card")
	}

	if card != nil && !requirements.CardCanBeUninitialised && !card.Session.IsInitialized() {
		http.Error(w, "card isn't initialised", http.StatusForbidden)
		return "", nil, errors.New("Card isn't initialised")
	}

	if card != nil && !requirements.CardCanBeLocked && !card.Session.IsUnlocked() {
		http.Error(w, "card is locked", http.StatusForbidden)
		return "", nil, errors.New("Card is locked")
	}

	return appId, card, nil
}
