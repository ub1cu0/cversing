import { useState, useEffect, useCallback } from 'react';
import { functionsData } from '../utils/dataSource';
import type { GameFunction } from '../utils/dataSource';



export type GameState = {
    score: number;
    highScore: number;
    currentFunction: GameFunction | null;
    isGameOver: boolean;
    status: 'playing' | 'correct' | 'incorrect';
    message: string;
};

export function useGameState() {
    const [state, setState] = useState<GameState>({
        score: 0,
        highScore: parseInt(localStorage.getItem('c-guessr-highscore') || '0'),
        currentFunction: null,
        isGameOver: false,
        status: 'playing',
        message: ''
    });

    const getRandomFunction = useCallback(() => {
        const randomIndex = Math.floor(Math.random() * functionsData.length);
        return functionsData[randomIndex];
    }, []);

    const startGame = useCallback(() => {
        setState(prev => ({
            ...prev,
            score: 0,
            isGameOver: false,
            status: 'playing',
            message: '',
            currentFunction: getRandomFunction()
        }));
    }, [getRandomFunction]);

    const nextRound = useCallback(() => {
        setState(prev => ({
            ...prev,
            status: 'playing',
            message: '',
            currentFunction: getRandomFunction()
        }));
    }, [getRandomFunction]);

    const submitGuess = useCallback((guess: string) => {
        if (!state.currentFunction) return;

        if (guess.toLowerCase() === state.currentFunction.name.toLowerCase()) {
            // Correct
            const newScore = state.score + 1;
            const newHighScore = Math.max(newScore, state.highScore);
            localStorage.setItem('c-guessr-highscore', newHighScore.toString());

            setState(prev => ({
                ...prev,
                score: newScore,
                highScore: newHighScore,
                status: 'correct',
                message: 'Correct! +1 Point'
            }));

            // Auto advance after small delay? Or manual?
            // For now, let user click "Next" or auto-advance
            setTimeout(() => nextRound(), 1500);

        } else {
            // Incorrect - Game Over in Infinite Mode
            setState(prev => ({
                ...prev,
                status: 'incorrect',
                isGameOver: true,
                message: `Game Over! It was ${state.currentFunction?.name}`
            }));
        }
    }, [state.currentFunction, state.score, state.highScore, nextRound]);

    // Initial load
    useEffect(() => {
        if (!state.currentFunction) {
            startGame();
        }
    }, []);

    return {
        state,
        startGame,
        submitGuess,
        allFunctionNames: functionsData.map(f => f.name)
    };
}
