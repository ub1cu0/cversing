import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import GameLayout from './components/layout/GameLayout';
import Home from './pages/Home';
import Infinite from './pages/Infinite';

import Daily from './pages/Daily';
import Wiki from './pages/Wiki';

function App() {
  return (
    <BrowserRouter>
      <GameLayout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/infinite" element={<Infinite />} />
          <Route path="/daily" element={<Daily />} />
          <Route path="/wiki" element={<Wiki />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </GameLayout>
    </BrowserRouter>
  );
}

export default App;
