package card

import (
	"fmt"

	"github.com/GridPlus/keycard-go/io"
	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/orchestrator"
)

type Card struct {
	Reader  string
	Session *orchestrator.Session
}

type CardManager struct {
	Cards              []*Card
	NewCardChannel     chan string
	RemovedCardChannel chan string
}

func NewCardManager() *CardManager {
	newReaderChannel := make(chan SmartCard)
	removedReaderChannel := make(chan string)
	go watchSmartCardStateChange(newReaderChannel, removedReaderChannel)

	sm := CardManager{
		NewCardChannel:     make(chan string),
		RemovedCardChannel: make(chan string),
	}

	go func() {
		for {
			select {
			case newReader := <-newReaderChannel:
				sm.addCard(newReader)
			case removedReader := <-removedReaderChannel:
				sm.removeCard(removedReader)
			}
		}
	}()

	return &sm
}

func (sm *CardManager) GetCard(cardId string) *Card {
	var card *Card

	for _, c := range sm.Cards {
		if c.Session.GetName() == cardId {
			card = c
		}
	}

	return card
}

func (sm *CardManager) addCard(sc SmartCard) {
	cs := card.NewPhononCommandSet(io.NewNormalChannel(sc.Card))
	session, err := orchestrator.NewSession(cs)
	if err != nil {
		fmt.Println("Unable to create a new session with card", err)
	}

	s := Card{
		Reader:  sc.Reader,
		Session: session,
	}

	sm.Cards = append(sm.Cards, &s)

	sm.NewCardChannel <- s.Session.GetName()
}

func (sm *CardManager) removeCard(reader string) {
	var card *Card
	var updatedCards []*Card

	for _, c := range sm.Cards {
		if c.Reader == reader {
			card = c
		} else {
			updatedCards = append(updatedCards, c)

		}
	}

	if card != nil {
		sm.RemovedCardChannel <- card.Session.GetName()
	}

	sm.Cards = updatedCards
}