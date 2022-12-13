package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	r.HandleFunc("/permissions", web.listPermissions).Methods("GET")
	r.HandleFunc("/permissions", web.requestPermissions).Methods("POST")

	r.HandleFunc("/cards", web.listCards).Methods("GET")
	r.HandleFunc("/cards/{cardId}/unlock", web.requestUnlock).Methods("POST")
	r.HandleFunc("/cards/{cardId}/name", web.setCardName).Methods("POST")
	r.HandleFunc("/cards/{cardId}/phonons", web.listPhonons).Methods("GET")
	r.HandleFunc("/cards/{cardId}/phonons", web.createPhonon).Methods("POST")
	r.HandleFunc("/cards/{cardId}/phonons", web.requestRedeemPhonon).Methods("DELETE")

	r.HandleFunc("/admin/permissions", web.adminAddPermissions).Methods("POST")
	r.HandleFunc("/admin/cards/{cardId}/unlock", web.adminUnlock).Methods("POST")
	r.HandleFunc("/admin/cards/{cardId}/phonons", web.adminRedeemPhonon).Methods("DELETE")

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

func (web *WebServer) listPermissions(w http.ResponseWriter, r *http.Request) {
	appId := getAppIdFromRequest(r)

	permissions := web.permissions.GetPermissions(appId)
	// go likes to encode empty arrays as nil. This hack ensures the correct JSON is returned.
	if len(permissions) == 0 {
		permissions = make([]string, 0)
	}

	responseBody := &interfaces.GetPermissionsResponseBody{
		Permissions: permissions,
	}

	json.NewEncoder(w).Encode(responseBody)
}

func (web *WebServer) requestPermissions(w http.ResponseWriter, r *http.Request) {
	appId := getAppIdFromRequest(r)

	var body interfaces.RequestPermissionsRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	areValid, invalid := permission.ArePermissionsValid(body.Permissions)

	if !areValid {
		http.Error(w, "invalid permissions: "+strings.Join(invalid, ","), http.StatusBadRequest)
		return
	}

	newPermissions := web.permissions.GetNewPermissions(appId, body.Permissions)

	if body.AdminToken != nil {
		if *body.AdminToken != web.AdminToken {
			http.Error(w, "invalid admin token", http.StatusForbidden)
			return
		}
		web.adminSessionId = appId
	} else {
		payload := interfaces.NewPermissionRequestEvent(appId, newPermissions)
		sendEvent(web.adminSessionId, payload, web)
	}

	json.NewEncoder(w).Encode(&interfaces.SuccessResponse{
		Success: true,
	})
}

func (web *WebServer) listCards(w http.ResponseWriter, r *http.Request) {
	if !web.hasPermission(permission.PERMISSION_READ_CARDS, w, r) {
		return
	}

	cards := interfaces.CardsToHttpCards(web.cards.Cards)

	// go likes to encode empty arrays as nil. This hack ensures the correct JSON is returned.
	if len(cards) == 0 {
		cards = make([]interfaces.Card, 0)
	}
	responseBody := interfaces.GetCardsResponseBody{
		Cards: cards,
	}

	json.NewEncoder(w).Encode(responseBody)
}

func (web *WebServer) setCardName(w http.ResponseWriter, r *http.Request) {
	if !web.hasPermission(permission.PERMISSION_SET_CARD_NAME, w, r) {
		return
	}

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	card := web.cards.GetCard(cardId)
	if card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	if !card.Session.IsUnlocked() {
		http.Error(w, "card locked", http.StatusForbidden)
		return
	}

	var body interfaces.SetCardNameRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = card.Session.SetName(body.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(interfaces.SuccessResponse{
		Success: true,
	})
}

func (web *WebServer) requestUnlock(w http.ResponseWriter, r *http.Request) {
	if !web.hasPermission(permission.PERMISSION_READ_CARDS, w, r) {
		return
	}

	appId := getAppIdFromRequest(r)

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	card := web.cards.GetCard(cardId)
	if card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	if !card.Session.IsUnlocked() {
		payload := interfaces.NewCardUnlockRequestEvent(appId, cardId)
		sendEvent(web.adminSessionId, payload, web)
	}

	json.NewEncoder(w).Encode(interfaces.SuccessResponse{
		Success: true,
	})
}

func (web *WebServer) listPhonons(w http.ResponseWriter, r *http.Request) {
	if !web.hasPermission(permission.PERMISSION_READ_PHONONS, w, r) {
		return
	}

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	card := web.cards.GetCard(cardId)
	if card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	if !card.Session.IsUnlocked() {
		http.Error(w, "card locked", http.StatusForbidden)
		return
	}

	phonons, err := card.Session.ListPhonons(0, 0, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, p := range phonons {
		if p.PubKey == nil {
			p.PubKey, err = card.Session.GetPhononPubKey(p.KeyIndex, p.CurveType)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	httpPhonons := interfaces.PhononsToHttpPhonons(phonons)

	json.NewEncoder(w).Encode(interfaces.GetPhononsResponseBody{
		Phonons: httpPhonons,
	})
}

func (web *WebServer) createPhonon(w http.ResponseWriter, r *http.Request) {
	if !web.hasPermission(permission.PERMISSION_CREATE_PHONONS, w, r) {
		return
	}

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	card := web.cards.GetCard(cardId)
	if card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	if !card.Session.IsUnlocked() {
		http.Error(w, "card locked", http.StatusForbidden)
		return
	}

	index, publicKey, err := card.Session.CreatePhonon()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendPhononEvent(interfaces.SOCKET_EVENT_PHONON_CREATED, web, cardId, uint16(index))

	json.NewEncoder(w).Encode(interfaces.Phonon{
		Index:     uint16(index),
		PublicKey: publicKey.String(),
	})
}

func (web *WebServer) requestRedeemPhonon(w http.ResponseWriter, r *http.Request) {
	if !web.hasPermission(permission.PERMISSION_READ_PHONONS, w, r) {
		return
	}

	appId := getAppIdFromRequest(r)

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	card := web.cards.GetCard(cardId)
	if card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	if !card.Session.IsUnlocked() {
		http.Error(w, "card locked", http.StatusForbidden)
		return
	}

	var body interfaces.RequestRedeemPhononRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	phonons, err := card.Session.ListPhonons(0, 0, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	foundPhonon := false

	for _, phonon := range phonons {
		if phonon.KeyIndex == model.PhononKeyIndex(body.Index) {
			foundPhonon = true
			break
		}
	}

	if !foundPhonon {
		http.Error(w, "phonon not found", http.StatusNotFound)
		return
	}

	payload := interfaces.NewRedeemRequestEvent(appId, cardId, body.Index)
	sendEvent(web.adminSessionId, payload, web)

	json.NewEncoder(w).Encode(interfaces.SuccessResponse{
		Success: true,
	})
}

func (web *WebServer) adminRedeemPhonon(w http.ResponseWriter, r *http.Request) {
	if !web.isAdmin(w, r) {
		return
	}

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	card := web.cards.GetCard(cardId)
	if card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	if !card.Session.IsUnlocked() {
		http.Error(w, "card locked", http.StatusForbidden)
		return
	}

	var body interfaces.RedeemPhononRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	phonons, err := card.Session.ListPhonons(0, 0, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	foundPhonon := false

	for _, phonon := range phonons {
		if phonon.KeyIndex == model.PhononKeyIndex(body.Index) {
			foundPhonon = true
			break
		}
	}

	if !foundPhonon {
		http.Error(w, "phonon not found", http.StatusNotFound)
		return
	}

	privateKey, err := card.Session.DestroyPhonon(model.PhononKeyIndex(body.Index))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	privateKeyHex := hex.EncodeToString(crypto.FromECDSA(privateKey))

	if body.AppId != nil {
		sendEvent(*body.AppId, interfaces.NewPhononRedeemActionedEvent(cardId, body.Index, privateKeyHex), web)
	}

	sendPhononEvent(interfaces.SOCKET_EVENT_PHONON_REDEEMED, web, cardId, body.Index)

	json.NewEncoder(w).Encode(interfaces.RedeemPhononResponseBody{
		PrivateKey: privateKeyHex,
	})
}

func (web *WebServer) adminUnlock(w http.ResponseWriter, r *http.Request) {
	if !web.isAdmin(w, r) {
		return
	}

	vars := mux.Vars(r)
	cardId := vars["cardId"]

	card := web.cards.GetCard(cardId)

	if card == nil {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}

	if card.Session.IsUnlocked() {
		json.NewEncoder(w).Encode(interfaces.SuccessResponse{
			Success: true,
		})
		return
	}

	var body interfaces.UnlockRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = card.Session.VerifyPIN(body.Pin)
	if err != nil {
		http.Error(w, "Failed to unlock card", http.StatusBadRequest)
		return
	}

	sendCardEvent(interfaces.SOCKET_EVENT_CARD_UNLOCKED, web, cardId)

	json.NewEncoder(w).Encode(interfaces.SuccessResponse{
		Success: true,
	})
}

func (web *WebServer) adminAddPermissions(w http.ResponseWriter, r *http.Request) {
	if !web.isAdmin(w, r) {
		return
	}

	var body interfaces.AddPermissionsRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	areValid, invalid := permission.ArePermissionsValid(body.Permissions)

	if !areValid {
		http.Error(w, "invalid permissions: "+strings.Join(invalid, ","), http.StatusBadRequest)
		return
	}

	web.permissions.AddPermissions(body.AppId, body.Permissions)

	allPermissions := web.permissions.GetPermissions(body.AppId)

	payload := interfaces.NewPermissionsEvent(body.Permissions, allPermissions)

	sendEvent(body.AppId, payload, web)

	json.NewEncoder(w).Encode(interfaces.SuccessResponse{
		Success: true,
	})
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

func (web *WebServer) hasPermission(requiredPermission string, w http.ResponseWriter, r *http.Request) bool {
	appId := getAppIdFromRequest(r)

	if appId == web.adminSessionId {
		return true
	}

	if web.permissions.HasPermission(appId, requiredPermission) {
		return true
	}

	w.WriteHeader(http.StatusForbidden)
	return false
}

func (web *WebServer) isAdmin(w http.ResponseWriter, r *http.Request) bool {
	appId := getAppIdFromRequest(r)

	if appId != web.adminSessionId {
		w.WriteHeader(http.StatusForbidden)
	}

	return appId == web.adminSessionId
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
