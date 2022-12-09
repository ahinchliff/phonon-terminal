export type Card = {
  id: string;
  isUnlocked: boolean;
  isInitialize: boolean;
};

export type Phonon = {
  index: number;
  publicKey: string;
};

export type Permission = 'READ_CARDS' | 'READ_PHONONS' | 'CREATE_PHONONS';

type CardEvent = {
  event: 'CARD_INSERTED' | 'CARD_REMOVED' | 'CARD_UNLOCKED';
  data: {
    cardId: string;
    cards: Card[];
  };
};

type PhononEvent = {
  event: 'PHONON_CREATED';
  data: {
    cardId: string;
    phononIndex: number;
  };
};

type PermissionRequestEvent = {
  event: 'NEW_PERMISSION_REQUEST';
  data: {
    appId: string;
    permissions: Permission[];
  };
};

type PermissionEvent = {
  event: 'PERMISSIONS_ADDED' | 'PERMISSIONS_REMOVED';
  data: {
    permissions: Permission[];
    allPermissions: Permission[];
  };
};

type CardUnlockRequestEvent = {
  event: 'NEW_CARD_UNLOCK_REQUEST';
  data: {
    appId: string;
    cardId: string;
  };
};

type EventHandlers = {
  onNewCardDetected?: (cardId: string, updatedCards: Card[]) => void;
  onCardRemoved?: (cardId: string, updatedCards: Card[]) => void;
  onCardUnlocked?: (cardId: string, updatedCards: Card[]) => void;
  onPermissionsUpdate?: (
    newPermission: Permission[],
    allPermissions: Permission[]
  ) => void;
  onPhononCreated?: (cardId: string, phononIndex: number) => void;
  adminOnPermissionRequest?: (appId: string, permissions: Permission[]) => void;
  adminOnCardUnlockRequest?: (appId: string, cardId: string) => void;
};

export default class PhononTerminal {
  private socket!: WebSocket;
  constructor(private port: number, private eventHandlers: EventHandlers) {}

  public init = async (): Promise<Permission[]> => {
    const permissions = await this.fetchPermissions();
    this.setupSockets();
    return permissions;
  };

  public fetchPermissions = async (): Promise<Permission[]> => {
    const response = await this.send<{
      permissions: Permission[];
    }>('GET', '/permissions');
    return response.permissions;
  };

  public requestPermissions = async (
    permissions: Permission[],
    adminToken?: string
  ): Promise<void> => {
    await this.send<{
      success: boolean;
    }>('POST', '/permissions', {
      permissions,
      adminToken,
    });
  };

  public requestCardUnlock = async (cardId: string): Promise<void> => {
    await this.send<void>('POST', `/cards/${cardId}/unlock`);
  };

  public fetchCards = async (): Promise<Card[]> => {
    const response = await this.send<{
      cards: Card[];
    }>('GET', '/cards');
    return response.cards;
  };

  public fetchPhonons = async (cardId: string): Promise<Phonon[]> => {
    const response = await this.send<{ phonons: Phonon[] }>(
      'GET',
      `/cards/${cardId}/phonons`
    );
    return response.phonons;
  };

  public createPhonon = async (cardId: string): Promise<Phonon> => {
    const response = await this.send<Phonon>(
      'POST',
      `/cards/${cardId}/phonons`
    );
    return response;
  };

  public adminUnlockCard = async (
    cardId: string,
    pin: string
  ): Promise<void> => {
    await this.send<void>('POST', `/admin/cards/${cardId}/unlock`, { pin });
  };

  public adminAddPermissions = async (
    appId: string,
    permissions: Permission[]
  ): Promise<void> => {
    await this.send<void>('POST', `/admin/permissions`, { appId, permissions });
  };

  private setupSockets = () => {
    this.socket = new WebSocket(`ws://localhost:${this.port}/ws`);

    this.socket.onmessage = ({ data }: MessageEvent<string>) => {
      const event = JSON.parse(data) as
        | CardEvent
        | PhononEvent
        | PermissionEvent
        | PermissionRequestEvent
        | CardUnlockRequestEvent;

      console.log('NEW EVENT', event);

      switch (event.event) {
        case 'CARD_INSERTED':
          this.eventHandlers.onNewCardDetected?.(
            event.data.cardId,
            event.data.cards
          );
          break;
        case 'CARD_REMOVED':
          this.eventHandlers.onCardRemoved?.(
            event.data.cardId,
            event.data.cards
          );
          break;
        case 'PERMISSIONS_ADDED':
          this.eventHandlers.onPermissionsUpdate?.(
            event.data.permissions,
            event.data.allPermissions
          );
          break;
        case 'CARD_UNLOCKED':
          this.eventHandlers.onCardUnlocked?.(
            event.data.cardId,
            event.data.cards
          );
          break;
        case 'NEW_PERMISSION_REQUEST':
          this.eventHandlers.adminOnPermissionRequest?.(
            event.data.appId,
            event.data.permissions
          );
          break;
        case 'NEW_CARD_UNLOCK_REQUEST':
          this.eventHandlers.adminOnCardUnlockRequest?.(
            event.data.appId,
            event.data.cardId
          );
          break;
        case 'NEW_CARD_UNLOCK_REQUEST':
          this.eventHandlers.adminOnCardUnlockRequest?.(
            event.data.appId,
            event.data.cardId
          );
          break;
        case 'PHONON_CREATED':
          this.eventHandlers.onPhononCreated?.(
            event.data.cardId,
            event.data.phononIndex
          );
          break;
      }
    };
  };

  private send = async <T>(
    method: string,
    path: string,
    body?: Object
  ): Promise<T> => {
    const response = await fetch(`http://localhost:${this.port}${path}`, {
      credentials: 'include',
      method,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json;charset=UTF-8',
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    return response.json();
  };
}
