package interfaces

import (
	"github.com/GridPlus/phonon-client/model"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/card"
)

type SuccessResponse struct {
	Success bool `json:"success"`
}

type Card struct {
	Id           string `json:"id"`
	IsUnlocked   bool   `json:"isUnlocked"`
	IsInitialize bool   `json:"isInitialize"`
}

type Phonon struct {
	Index     uint16 `json:"index"`
	PublicKey string `json:"publicKey"`
}

type GetPermissionsResponseBody struct {
	Permissions []string `json:"permissions"`
}

type RequestPermissionsRequestBody struct {
	AdminToken  *string  `json:"adminToken"`
	Permissions []string `json:"permissions"`
}

type GetCardsResponseBody struct {
	Cards []Card `json:"cards"`
}

type UnlockRequestBody struct {
	Pin string `json:"pin"`
}

type AddPermissionsRequestBody struct {
	AppId       string   `json:"appId"`
	Permissions []string `json:"permissions"`
}

type RedeemPhononRequestBody struct {
	Index uint16 `json:"index"`
}

type RedeemPhononResponseBody struct {
	PrivateKey string `json:"PrivateKey"`
}

type GetPhononsResponseBody struct {
	Phonons []Phonon `json:"phonons"`
}

func CardsToHttpCards(cards []*card.Card) []Card {
	https := []Card{}
	for _, c := range cards {
		http := cardToHttpCard(c)
		https = append(https, http)
	}
	return https
}

func cardToHttpCard(card *card.Card) Card {
	return Card{
		Id:           card.Session.GetName(),
		IsUnlocked:   card.Session.IsUnlocked(),
		IsInitialize: card.Session.IsInitialized(),
	}
}

func PhononsToHttpPhonons(phonons []*model.Phonon) []Phonon {
	https := []Phonon{}
	for _, p := range phonons {
		http := PhononToHttpPhonon(*p)
		https = append(https, http)
	}
	return https
}

func PhononToHttpPhonon(phonon model.Phonon) Phonon {
	return Phonon{
		Index:     phonon.KeyIndex,
		PublicKey: phonon.PubKey.String(),
	}
}