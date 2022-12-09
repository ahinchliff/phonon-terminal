import * as React from 'react';
import Client, { Card, Permission } from 'phonon-terminal-js';
import { GetAdminToken } from '../../wailsjs/go/app/App';

type CardStore = {
  cards: Card[];
  client: Client;
  requests: (PermissionRequest | UnlockRequest)[];
  acceptPermissions: (id: string) => Promise<void>;
};

type UnlockRequest = {
  type: 'Unlock';
  appId: string;
  cardId: string;
};

type PermissionRequest = {
  type: 'Permission';
  appId: string;
  permissions: Permission[];
};

const CardStoreContext = React.createContext<CardStore | undefined>(undefined);

export const CardStoreProvider: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  const [isAuthd, setIsAuthd] = React.useState<boolean>(false);
  const [cards, setCards] = React.useState<Card[]>([]);
  const [requests, setRequests] = React.useState<
    (PermissionRequest | UnlockRequest)[]
  >([]);

  const onNewCardDetected = React.useCallback((_: string, cardList: Card[]) => {
    setCards(cardList);
  }, []);

  const onCardRemoved = React.useCallback((_: string, cardList: Card[]) => {
    setCards(cardList);
  }, []);

  const onCardUnlocked = React.useCallback((_: string, cardList: Card[]) => {
    setCards(cardList);
  }, []);

  const adminOnPermissionRequest = React.useCallback(
    (appId: string, permissions: Permission[]) => {
      setRequests((current) => [
        ...current,
        { type: 'Permission', appId, permissions },
      ]);
    },
    []
  );

  const adminOnCardUnlockRequest = React.useCallback(
    (appId: string, cardId: string) => {
      setRequests((current) => [...current, { type: 'Unlock', appId, cardId }]);
    },
    []
  );

  const client = React.useRef(
    new Client(3001, {
      onNewCardDetected,
      onCardRemoved,
      onCardUnlocked,
      adminOnPermissionRequest,
      adminOnCardUnlockRequest,
    })
  ).current;

  React.useEffect(() => {
    (async () => {
      const adminToken = await GetAdminToken();
      await client.init();
      await client.requestPermissions([], adminToken);
      setIsAuthd(true);
    })();
  }, [client]);

  React.useEffect(() => {
    if (!isAuthd) {
      return;
    }

    (async () => {
      const newCards = await client.fetchCards();
      setCards(newCards);
    })();
  }, [client, isAuthd]);

  const acceptPermissions = React.useCallback(
    async (appId: string) => {
      const request = requests.find((p) => p.appId === appId);
      if (!request || request.type !== 'Permission') {
        return;
      }

      await client.adminAddPermissions(appId, request.permissions);

      setRequests((exisitng) => exisitng.filter((r) => r.appId !== appId));
    },
    [requests, client]
  );

  const value = React.useMemo(
    () => ({
      cards,
      client,
      requests,
      acceptPermissions,
    }),
    [cards, client, requests, acceptPermissions]
  );

  return (
    <CardStoreContext.Provider value={value}>
      {children}
    </CardStoreContext.Provider>
  );
};

export const useCardStore = (): CardStore => {
  const context = React.useContext(CardStoreContext);

  if (context === undefined) {
    throw new Error('useCardStore must be used within a CardStoreProvider');
  }
  return context;
};
