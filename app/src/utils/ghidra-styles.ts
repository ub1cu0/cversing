
export type Token = {
    text: string;
    type: 'type' | 'keyword' | 'function' | 'variable' | 'number' | 'string' | 'comment' | 'plain' | 'symbol';
    className: string;
};

// Ghidra-like definitions
const TYPES = new Set([
    'void', 'char', 'int', 'long', 'size_t', 'undefined', 'undefined1',
    'undefined2', 'undefined4', 'undefined8', 'byte', 'uint', 'ushort', 'float', 'double', 'bool'
]);

const KEYWORDS = new Set([
    'if', 'else', 'do', 'while', 'for', 'return', 'switch', 'case',
    'default', 'break', 'continue', 'goto', 'sizeof'
]);

// Simple regex-based lexer
export function tokenizeCode(code: string): Token[] {
    const tokens: Token[] = [];
    let current = 0;

    while (current < code.length) {
        const char = code[current];

        // Whitespace
        if (/\s/.test(char)) {
            tokens.push({ text: char, type: 'plain', className: '' });
            current++;
            continue;
        }

        // Strings/Chars
        if (char === '"' || char === "'") {
            let value = char;
            current++;
            while (current < code.length && code[current] !== char) {
                if (code[current] === '\\') {
                    value += code[current] + (code[current + 1] || '');
                    current += 2;
                } else {
                    value += code[current];
                    current++;
                }
            }
            if (current < code.length) {
                value += code[current]; // Closing quote
                current++;
            }
            tokens.push({ text: value, type: 'string', className: 'text-green-400' });
            continue;
        }

        // Numbers (Hex or Decimal)
        if (/[0-9]/.test(char)) {
            let value = '';
            if (char === '0' && code[current + 1] === 'x') {
                value = '0x';
                current += 2;
                while (current < code.length && /[0-9a-fA-F]/.test(code[current])) {
                    value += code[current];
                    current++;
                }
            } else {
                while (current < code.length && /[0-9]/.test(code[current])) {
                    value += code[current];
                    current++;
                }
            }
            tokens.push({ text: value, type: 'number', className: 'text-orange-400' });
            continue;
        }

        // Identifiers (Keywords, Types, Functions, Variables)
        if (/[a-zA-Z_]/.test(char)) {
            let value = '';
            while (current < code.length && /[a-zA-Z0-9_]/.test(code[current])) {
                value += code[current];
                current++;
            }

            // Check if it's a function call (followed by optional whitespace then '(')
            const isFunction = /^\s*\(/.test(code.slice(current));

            if (TYPES.has(value)) {
                tokens.push({ text: value, type: 'type', className: 'text-teal-400 font-bold' });
            } else if (KEYWORDS.has(value)) {
                tokens.push({ text: value, type: 'keyword', className: 'text-purple-400 font-bold' });
            } else if (isFunction) {
                tokens.push({ text: value, type: 'function', className: 'text-blue-400' });
            } else if (/^(param_|local_|uVar|iVar|pcVar|cVar|puVar|__)/.test(value)) {
                tokens.push({ text: value, type: 'variable', className: 'text-red-300' });
            } else {
                // Default identifier styling
                tokens.push({ text: value, type: 'variable', className: 'text-zinc-300' });
            }
            continue;
        }

        // Symbols / Operators
        tokens.push({ text: char, type: 'symbol', className: 'text-zinc-500' });
        current++;
    }

    return tokens;
}
