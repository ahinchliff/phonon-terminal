package main

import (
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/card"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/web"
)

func main() {
	cardManager := card.NewCardManager()
	web, _ := web.New(cardManager, web.CreateSecret(), "./permissions.json")
	web.Start(":3001")
}
