package card

import (
	"fmt"

	"github.com/GridPlus/keycard-go/io"
	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/config"
	"github.com/GridPlus/phonon-client/orchestrator"
	"github.com/google/uuid"
)

type Card struct {
	Reader  string
	Session *orchestrator.Session
	IsMock  bool
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
		if c.Session.GetCardId() == cardId {
			card = c
		}
	}

	return card
}

func (sm *CardManager) CreateMockCard(initialise bool) (string, error) {
	c, err := card.NewMockCard(initialise, false)
	if err != nil {
		return "", err
	}

	session, err := orchestrator.NewSession(c)
	if err != nil {
		return "", err
	}

	s := Card{
		Reader:  uuid.NewString(),
		Session: session,
		IsMock:  true,
	}

	sm.Cards = append(sm.Cards, &s)

	sm.NewCardChannel <- s.Session.GetCardId()

	return s.Session.GetCardId(), nil
}

func (sm *CardManager) ClearMockCards() {
	var updatedCards []*Card

	for _, c := range sm.Cards {
		if c.IsMock == false {
			updatedCards = append(updatedCards, c)
		}
	}

	sm.Cards = updatedCards
}

func (sm *CardManager) addCard(sc SmartCard) {
	// todo - look into what config needs to be passed down
	config := config.Config{}

	cs := card.NewPhononCommandSet(io.NewNormalChannel(sc.Card), config)
	session, err := orchestrator.NewSession(cs)
	if err != nil {
		fmt.Println("Unable to create a new session with card: ", err)
		return
	}

	s := Card{
		Reader:  sc.Reader,
		Session: session,
		IsMock:  false,
	}

	sm.Cards = append(sm.Cards, &s)

	sm.NewCardChannel <- s.Session.GetCardId()
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
		sm.RemovedCardChannel <- card.Session.GetCardId()
	}

	sm.Cards = updatedCards
}
