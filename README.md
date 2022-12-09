# Phonon Terminal

Currently a mono repo. Once ready for release only the contents of `./phonon-terminal` will be included in the repo. This is my first golang project so feedback is very welcome.

## Phonon Terminal

A web server written in golang designed to be run on a user's local machine.

- endpoints to access card functionality
- endpoints to request and grant permissions
- web sockets for pushing card and permission changes to subscribers
- logic to watch for card reader state changes

## Components

### Phonon Terminal JS

Simple http and web socket client for accessing a local running phonon terminal

### Native Wallet

An example of how a native app can integrate the phonon terminal package and grant itself admin privileges.

- built using Wails and a React front end
- imports the phonon terminal package into the backend and phonon terminal js sdk into the front end
- most of the native logic is around loading config and granting admin permissions to the front end

### Web Wallet

An example of how a web app is able to request permissions, subscribe to card events and access card functionality.

- built use React
- imports the phonon terminal js sdk into the front end

## Running

1. Install wails (https://wails.io/docs/gettingstarted/installation)
2. In `./native-wallet/front-end` run `yarn`
3. In `./native-wallet/front-end` run `wails dev`
4. In `./web-wallet` run `yarn && yarn start`
