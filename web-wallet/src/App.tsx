import { Card } from 'phonon-terminal-js';
import React from 'react';
import { useCardStore } from './stores/CardStore';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <Content />
      </header>
    </div>
  );
}

export default App;

const Content: React.FC = () => {
  const { cards, permissions } = useCardStore();

  if (!permissions.includes('READ_CARDS')) {
    return <p>Waiting for "read card" permission to be granted</p>;
  }

  if (!cards.length) {
    return <p>No cards connected</p>;
  }

  return (
    <div>
      {cards.map((c) => (
        <CardListItem card={c} />
      ))}
    </div>
  );
};

const CardListItem: React.FC<{ card: Card }> = ({ card }) => {
  const { client } = useCardStore();

  const [requestingUnlock, setRequestingUnlock] =
    React.useState<boolean>(false);

  const requestUnlock = () => {
    setRequestingUnlock(true);
    client.requestCardUnlock(card.id);
  };

  return (
    <div>
      <span style={{ marginRight: 5, fontWeight: 'bold' }}>{card.id}</span>
      <span style={{ marginRight: 20 }}>
        ({card.isUnlocked ? 'Unlocked' : 'Locked'})
      </span>
      {!card.isUnlocked && (
        <button onClick={requestUnlock} disabled={requestingUnlock}>
          Unlock
        </button>
      )}
    </div>
  );
};
