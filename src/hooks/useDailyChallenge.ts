import { useState, useEffect, useCallback } from 'react';
import { functionsData } from '../utils/dataSource';
import type { GameState } from './useGameState';

// Simple but robust hashing for daily selection
const getDailyIndex = async (totalFunctions: number, salt: string = "CVERSING-salt-v1"): Promise<number> => {
    // Get current date string YYYY-MM-DD
    const date = new Date().toISOString().split('T')[0];
    const input = `${salt}-${date}`;

    // Create a hash using the Web Crypto API
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert first 4 bytes to an integer
    const hashArray = new Uint8Array(hashBuffer);
    const hashInt = (hashArray[0] << 24) | (hashArray[1] << 16) | (hashArray[2] << 8) | hashArray[3];

    // Use modulo to get an index ensuring it's always positive
    return Math.abs(hashInt) % totalFunctions;
};

const getDateString = () => new Date().toISOString().split('T')[0];

export function useDailyChallenge() {
    const [gameState, setGameState] = useState<GameState>({
        score: 0,
        highScore: 0,
        currentFunction: null,
        isGameOver: false,
        status: 'playing',
        message: ''
    });

    const [streak, setStreak] = useState(0);
    const [hasPlayedToday, setHasPlayedToday] = useState(false);

    useEffect(() => {
        const initializeDaily = async () => {
            // 1. Get today's function index securely
            const index = await getDailyIndex(functionsData.length);
            const dailyFunc = functionsData[index];

            // 2. Check local storage for today's progress
            const today = new Date().toISOString().split('T')[0];
            const lastPlayed = localStorage.getItem('daily_last_played');
            const streakCount = parseInt(localStorage.getItem('daily_streak') || '0', 10);

            // Update state
            setStreak(streakCount);

            if (lastPlayed === today) {
                // User already played today
                const savedStatus = localStorage.getItem('daily_status') as 'correct' | 'incorrect' | null;
                setGameState({
                    score: 0,
                    highScore: 0,
                    currentFunction: dailyFunc,
                    isGameOver: true,
                    status: savedStatus || 'playing', // Should ideally allow re-viewing the result
                    message: savedStatus === 'correct' ? 'Come back tomorrow!' : 'Better luck next time!'
                });
                setHasPlayedToday(true);
            } else {
                // New day, new challenge
                setGameState({
                    score: 0,
                    highScore: 0,
                    currentFunction: dailyFunc,
                    isGameOver: false,
                    status: 'playing',
                    message: ''
                });
                setHasPlayedToday(false);

                // If they missed yesterday (skipped a day), reset streak
                if (lastPlayed) {
                    const lastDate = new Date(lastPlayed);
                    const yesterday = new Date();
                    yesterday.setDate(yesterday.getDate() - 1);

                    // Compare dates simply
                    if (lastDate.toISOString().split('T')[0] !== yesterday.toISOString().split('T')[0]) {
                        // Streak broken if not yesterday
                        // Logic could be more complex here but this is a simple check
                    }
                }
            }
        };

        initializeDaily();
    }, []);

    const submitGuess = useCallback((guess: string) => {
        if (hasPlayedToday || !gameState.currentFunction) return;

        const today = getDateString();

        const match = guess.toLowerCase() === gameState.currentFunction.name.toLowerCase();

        if (match) {
            // Correct
            const newStreak = streak + 1;
            setStreak(newStreak);
            localStorage.setItem('daily_streak', newStreak.toString());
            localStorage.setItem('daily_status', 'correct');
            localStorage.setItem('daily_last_played', today);

            setGameState(prev => ({
                ...prev,
                status: 'correct',
                isGameOver: true,
                message: 'Correct! See you tomorrow!'
            }));
            setHasPlayedToday(true);
        } else {
            // Incorrect
            setStreak(0);
            localStorage.setItem('daily_streak', '0');
            localStorage.setItem('daily_status', 'incorrect');
            localStorage.setItem('daily_last_played', today);

            setGameState(prev => ({
                ...prev,
                status: 'incorrect',
                isGameOver: true,
                message: `Incorrect! It was ${gameState.currentFunction?.name}`
            }));
            setHasPlayedToday(true);
        }
    }, [gameState.currentFunction, hasPlayedToday, streak]);

    return {
        gameState,
        submitGuess,
        streak,
        hasPlayedToday,
        allFunctionNames: functionsData.map(f => f.name)
    };
}
