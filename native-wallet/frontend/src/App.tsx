import { useCardStore } from './stores/CardStore';

const App = () => {
  const { cards, client, requests, acceptPermissions } = useCardStore();

  const onUnlock = async (cardId: string) => {
    await client.adminUnlockCard(cardId, '111111');
  };

  const createPhonon = async (cardId: string) => {
    const result = await client.createPhonon(cardId);
    console.log(result);
  };

  const fetchPhonons = async (cardId: string) => {
    const result = await client.fetchPhonons(cardId);
    console.log(result);
  };

  return (
    <div className="flex-1">
      <h1>Native App</h1>

      <h2>Requests</h2>
      {requests.map((r) => {
        return (
          <div key={r.appId}>
            <p>
              {r.appId} -{' '}
              {r.type === 'Permission' ? r.permissions.join(', ') : 'Unlock'}
            </p>
            <button
              onClick={
                r.type === 'Permission'
                  ? () => acceptPermissions(r.appId)
                  : () => onUnlock(r.cardId)
              }
            >
              Approve
            </button>
          </div>
        );
      })}

      <h2>Card List</h2>
      {cards.map((c) => (
        <div key={c.id}>
          {c.id} - Unlocked: {`${c.isUnlocked}`}, Initialised:{' '}
          {`${c.isInitialize}`}
          <div>
            <button onClick={() => onUnlock(c.id)}>Unlock</button>
          </div>
          <div>
            <button onClick={() => fetchPhonons(c.id)}>fetch phonons</button>
          </div>
          <div>
            <button onClick={() => createPhonon(c.id)}>create phonon</button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default App;
