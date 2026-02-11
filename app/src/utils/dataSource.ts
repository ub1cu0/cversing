import rawData from '../data/functions.json';

export interface GameFunction {
    id: string;
    name: string;
    code: string;
    description: string;
    difficulty: string;
}

// Helper to normalize data that might be missing fields from raw Ghidra exports
const normalizeFunction = (data: any, index: number): GameFunction => {
    return {
        id: data.id || `auto-${data.name}-${index}`,
        name: data.name || 'Unknown Function',
        code: data.code || '',
        description: data.description || 'Function extracted from binary',
        difficulty: data.difficulty || 'Medium'
    };
};

export const functionsData: GameFunction[] = (rawData as any[]).map(normalizeFunction);
