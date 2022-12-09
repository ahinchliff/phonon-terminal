package interfaces

var (
	SOCKET_EVENT_PERMISSIONS_ADDED   = "PERMISSIONS_ADDED"
	SOCKET_EVENT_PERMISSIONS_REMOVED = "PERMISSIONS_REMOVED"
	SOCKET_EVENT_CARD_UNLOCKED       = "CARD_UNLOCKED"
	SOCKET_EVENT_CARD_INSERTED       = "CARD_INSERTED"
	SOCKET_EVENT_CARD_REMOVED        = "CARD_REMOVED"
	SOCKET_EVENT_PHONON_CREATED      = "PHONON_CREATED"

	// admin
	SOCKET_EVENT_NEW_PERMISSION_REQUEST  = "NEW_PERMISSION_REQUEST"
	SOCKET_EVENT_NEW_CARD_UNLOCK_REQUEST = "NEW_CARD_UNLOCK_REQUEST"
)

type SocketEvent[T any] struct {
	Event string `json:"event"`
	Data  T      `json:"data"`
}

type PermissionRequestEventPayload struct {
	AppId       string   `json:"appId"`
	Permissions []string `json:"permissions"`
}

type PhononEventPayload struct {
	CardId      string `json:"cardId"`
	PhononIndex uint16 `json:"phononIndex"`
}

type CardEventPayload struct {
	CardId string `json:"cardId"`
	Cards  []Card `json:"cards"`
}

type PermissionsEventPayload struct {
	Permissions    []string `json:"permissions"`
	AllPermissions []string `json:"allPermissions"`
}

type CardUnlockRequestEventPayload struct {
	AppId  string `json:"appId"`
	CardId string `json:"cardId"`
}

func NewCardEvent(event string, cardId string, cards []Card) SocketEvent[CardEventPayload] {
	return SocketEvent[CardEventPayload]{
		Event: event,
		Data: CardEventPayload{
			CardId: cardId,
			Cards:  cards,
		},
	}
}

func NewPhononEvent(event string, cardId string, phononIndex uint16) SocketEvent[PhononEventPayload] {
	return SocketEvent[PhononEventPayload]{
		Event: event,
		Data: PhononEventPayload{
			CardId:      cardId,
			PhononIndex: phononIndex,
		},
	}
}

func NewPermissionRequestEvent(appId string, permissions []string) SocketEvent[PermissionRequestEventPayload] {
	return SocketEvent[PermissionRequestEventPayload]{
		Event: SOCKET_EVENT_NEW_PERMISSION_REQUEST,
		Data: PermissionRequestEventPayload{
			AppId:       appId,
			Permissions: permissions,
		},
	}
}

func NewCardUnlockRequestEvent(appId string, cardId string) SocketEvent[CardUnlockRequestEventPayload] {
	return SocketEvent[CardUnlockRequestEventPayload]{
		Event: SOCKET_EVENT_NEW_CARD_UNLOCK_REQUEST,
		Data: CardUnlockRequestEventPayload{
			AppId:  appId,
			CardId: cardId,
		}}
}

func NewPermissionsEvent(permissions []string, allPermissions []string) SocketEvent[PermissionsEventPayload] {
	return SocketEvent[PermissionsEventPayload]{
		Event: SOCKET_EVENT_PERMISSIONS_ADDED,
		Data: PermissionsEventPayload{
			Permissions:    permissions,
			AllPermissions: allPermissions,
		}}
}
