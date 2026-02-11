import { useDailyChallenge } from '../hooks/useDailyChallenge';
import CodeViewer from '../components/game/CodeViewer';
import GameInput from '../components/game/GameInput';
import { motion, AnimatePresence } from 'framer-motion';
import { Calendar, CheckCircle2, XCircle } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Daily() {
    const { gameState, submitGuess, streak, hasPlayedToday, allFunctionNames } = useDailyChallenge();

    return (
        <div className="max-w-3xl mx-auto space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-2">
                    <Calendar className="text-blue-400" />
                    Daily Challenge
                </h2>
                <div className="flex items-center gap-2 px-4 py-2 bg-surfaceHighlight rounded-lg border border-white/5">
                    <span className="text-zinc-400 text-sm font-bold uppercase tracking-wider">Streak</span>
                    <span className="text-xl font-mono font-bold text-white">{streak}</span>
                </div>
            </div>

            <AnimatePresence mode='wait'>
                {gameState.currentFunction ? (
                    <motion.div
                        key={gameState.currentFunction.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-6"
                    >
                        <CodeViewer code={gameState.currentFunction.code} />

                        {!hasPlayedToday ? (
                            <GameInput options={allFunctionNames} onGuess={submitGuess} />
                        ) : (
                            <div className={`p-6 rounded-xl border ${gameState.status === 'correct'
                                    ? 'bg-green-500/10 border-green-500/20'
                                    : 'bg-red-500/10 border-red-500/20'
                                } text-center space-y-4`}>
                                <div className="flex justify-center">
                                    {gameState.status === 'correct' ? (
                                        <CheckCircle2 className="w-12 h-12 text-green-400" />
                                    ) : (
                                        <XCircle className="w-12 h-12 text-red-400" />
                                    )}
                                </div>
                                <h3 className="text-2xl font-bold">
                                    {gameState.status === 'correct' ? 'Well Done!' : 'Better luck next time!'}
                                </h3>
                                <p className="text-zinc-400">
                                    The function was <span className="font-mono text-white font-bold">{gameState.currentFunction.name}</span>.
                                </p>
                                <p className="text-sm text-zinc-500">
                                    Come back tomorrow for a new challenge!
                                </p>
                                <Link to="/infinite" className="inline-block px-6 py-2 bg-surfaceHighlight hover:bg-zinc-700 rounded-lg transition-colors font-medium">
                                    Play Infinite Mode
                                </Link>
                            </div>
                        )}
                    </motion.div>
                ) : (
                    <div className="text-center py-20">Loading daily challenge...</div>
                )}
            </AnimatePresence>
        </div>
    );
}
