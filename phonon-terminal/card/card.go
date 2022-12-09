package card

import (
	"time"

	"github.com/ebfe/scard"
)

type SmartCard struct {
	Reader string
	Card   *scard.Card
}

func watchSmartCardStateChange(newFoundCardChannel chan<- SmartCard, removedCardChannel chan<- string) {
	cardContext, _ := scard.EstablishContext()
	var readerStates []scard.ReaderState

	go func() {
		for {
			activeReaders, _ := cardContext.ListReaders()

			for _, activeReader := range activeReaders {
				isNew := true
				for _, readerState := range readerStates {
					if readerState.Reader == activeReader {
						isNew = false
						break
					}
				}

				if isNew {
					readerStates = append(readerStates, scard.ReaderState{
						Reader:       activeReader,
						CurrentState: scard.StateUnaware,
					})
				}
			}

			time.Sleep(time.Second)
		}
	}()

	go func() {
		for {
			if len(readerStates) > 0 {
				for i := range readerStates {

					if !isConnectedState(readerStates[i].CurrentState) && isConnectedState(readerStates[i].EventState) {
						card, _ := cardContext.Connect(readerStates[i].Reader, scard.ShareShared, scard.ProtocolAny)
						smartCard := SmartCard{
							Card:   card,
							Reader: readerStates[i].Reader,
						}
						newFoundCardChannel <- smartCard
					}

					if isConnectedState(readerStates[i].CurrentState) && isDisconnectedState(readerStates[i].EventState) {
						removedCardChannel <- readerStates[i].Reader
					}
					readerStates[i].CurrentState = readerStates[i].EventState
				}
				cardContext.GetStatusChange(readerStates, -1)
			}
		}
	}()
}

func isConnectedState(state scard.StateFlag) bool {
	states := []scard.StateFlag{34, 32, 190, 290}
	for _, s := range states {
		if s == state {
			return true
		}
	}
	return false
}

func isDisconnectedState(state scard.StateFlag) bool {
	states := []scard.StateFlag{18, 6}
	for _, s := range states {
		if s == state {
			return true
		}
	}
	return false
}
