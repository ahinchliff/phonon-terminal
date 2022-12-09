package app

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/ahinchliff/phonon-terminal/phonon-terminal/card"
	"github.com/ahinchliff/phonon-terminal/phonon-terminal/web"
	"github.com/spf13/viper"
)

type Config struct {
	Secret string
}

type App struct {
	ctx         context.Context
	cardManager *card.CardManager
	web         *web.WebServer
}

func NewApp() *App {
	return &App{}
}

func (a *App) Startup(ctx context.Context) {
	cardManager := card.NewCardManager()

	path, err := getAppDirectory()
	if err != nil {
		fmt.Println("unable load app directory", err)
	}

	config, err := initOrLoadConfig(path)
	if err != nil {
		fmt.Println("unable to load config", err)
	}

	web, _ := web.New(cardManager, config.Secret, path+"permissions.json")

	go web.Start(":3001")

	a.cardManager = cardManager
	a.web = web
	a.ctx = ctx
}

func (a *App) GetAdminToken() string {
	return a.web.AdminToken
}

func initOrLoadConfig(directoryPath string) (config Config, err error) {
	if err != nil {
		return config, err
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yml")
	viper.AddConfigPath(directoryPath)

	err = viper.ReadInConfig()
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		println("creating config")
		secret := web.CreateSecret()
		viper.Set("Secret", secret)
		os.Mkdir(directoryPath, os.ModePerm)
		err = viper.SafeWriteConfigAs(directoryPath + "config.yml")
		if err != nil {
			fmt.Println("failed to write config: ", err)
			return config, err
		}
		err = viper.ReadInConfig()
		if err != nil {
			fmt.Println("failed to read config: ", err)
			return config, err
		}
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		fmt.Println("failed to unmarshal config: ", err)
		return config, nil
	}

	return config, nil
}

func getAppDirectory() (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin", "linux":
		return homedir + "/.phonon-desktop/", nil
	case "windows":
		return homedir + "\\.phonon-desktop\\", nil
	default:
		return "", fmt.Errorf("unable to set configuration path for %s", runtime.GOOS)
	}
}
