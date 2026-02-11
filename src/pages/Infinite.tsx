import { useGameState } from '../hooks/useGameState';
import CodeViewer from '../components/game/CodeViewer';
import GameInput from '../components/game/GameInput';
import { motion, AnimatePresence } from 'framer-motion';
import { Trophy, RefreshCw } from 'lucide-react';

export default function Infinite() {
    const { state, submitGuess, allFunctionNames, startGame } = useGameState();

    return (
        <div className="max-w-3xl mx-auto space-y-8">
            {/* Stats Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-surfaceHighlight rounded-xl border border-white/5">
                        <div className="text-xs text-zinc-500 uppercase tracking-wider font-bold mb-1">Score</div>
                        <div className="text-2xl font-mono font-bold text-white">{state.score}</div>
                    </div>
                    <div className="p-3 bg-surfaceHighlight rounded-xl border border-white/5">
                        <div className="text-xs text-zinc-500 uppercase tracking-wider font-bold mb-1">Best</div>
                        <div className="flex items-center gap-2 text-2xl font-mono font-bold text-yellow-500">
                            <Trophy size={20} />
                            {state.highScore}
                        </div>
                    </div>
                </div>

                {state.isGameOver && (
                    <button
                        onClick={startGame}
                        className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg font-bold transition-all shadow-lg shadow-primary/20"
                    >
                        <RefreshCw size={18} />
                        Play Again
                    </button>
                )}
            </div>

            {/* Game Area */}
            <AnimatePresence mode='wait'>
                {state.currentFunction && (
                    <motion.div
                        key={state.currentFunction.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        className="space-y-6"
                    >
                        <CodeViewer code={state.currentFunction.code} />

                        <div className="space-y-2">
                            <GameInput
                                options={allFunctionNames}
                                onGuess={submitGuess}
                                disabled={state.isGameOver || state.status === 'correct'}
                            />

                            {state.message && (
                                <motion.div
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    className={`text-center font-bold p-3 rounded-lg ${state.status === 'correct' ? 'bg-green-500/20 text-green-400' :
                                            state.status === 'incorrect' ? 'bg-red-500/20 text-red-400' : ''
                                        }`}
                                >
                                    {state.message}
                                </motion.div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
