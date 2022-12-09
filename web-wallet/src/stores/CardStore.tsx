import * as React from 'react';
import Client, { Card, Permission } from 'phonon-terminal-js';

type CardStore = {
  cards: Card[];
  permissions: Permission[];
  client: Client;
};

const CardStoreContext = React.createContext<CardStore | undefined>(undefined);

export const CardStoreProvider: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  const [cards, setCards] = React.useState<Card[]>([]);
  const [permissions, setPermissions] = React.useState<Permission[]>([]);

  const onNewCardDetected = React.useCallback((_: string, cardList: Card[]) => {
    setCards(cardList);
  }, []);

  const onCardRemoved = React.useCallback((_: string, cardList: Card[]) => {
    setCards(cardList);
  }, []);

  const onCardUnlocked = React.useCallback((_: string, cardList: Card[]) => {
    setCards(cardList);
  }, []);

  const onPermissionsUpdate = React.useCallback(
    (_: Permission[], permissions: Permission[]) => {
      setPermissions(permissions);
    },
    []
  );

  const client = React.useRef(
    new Client(3001, {
      onNewCardDetected,
      onCardRemoved,
      onCardUnlocked,
      onPermissionsUpdate,
    })
  ).current;

  React.useEffect(() => {
    (async () => {
      const permissions = await client.init();
      setPermissions(permissions);

      if (!permissions.includes('READ_CARDS')) {
        await client.requestPermissions(['READ_CARDS']);
      }
    })();
  }, [client]);

  React.useEffect(() => {
    if (!permissions.includes('READ_CARDS')) {
      return;
    }

    (async () => {
      const newCards = await client.fetchCards();
      setCards(newCards);
    })();
  }, [client, permissions]);

  const value = React.useMemo(
    () => ({
      cards,
      client,
      permissions,
    }),
    [cards, client, permissions]
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
