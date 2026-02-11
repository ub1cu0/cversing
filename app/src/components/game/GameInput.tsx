import { useState, useRef, useEffect } from 'react';
import { Search, Check } from 'lucide-react';
import clsx from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';

interface GameInputProps {
    options: string[];
    onGuess: (guess: string) => void;
    disabled?: boolean;
}

export default function GameInput({ options, onGuess, disabled }: GameInputProps) {
    const [query, setQuery] = useState('');
    const [isOpen, setIsOpen] = useState(false);
    const [focusedIndex, setFocusedIndex] = useState(-1);
    const inputRef = useRef<HTMLInputElement>(null);
    const wrapperRef = useRef<HTMLDivElement>(null);

    const filteredOptions = options.filter(opt =>
        opt.toLowerCase().includes(query.toLowerCase())
    ).slice(0, 5); // Limit to 5 suggestions

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const handleSubmit = (value: string) => {
        if (!value) return;
        onGuess(value);
        setQuery('');
        setIsOpen(false);
        setFocusedIndex(-1);
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setFocusedIndex(prev => (prev < filteredOptions.length - 1 ? prev + 1 : prev));
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setFocusedIndex(prev => (prev > 0 ? prev - 1 : -1));
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (focusedIndex >= 0 && filteredOptions[focusedIndex]) {
                handleSubmit(filteredOptions[focusedIndex]);
            } else if (query) {
                // Allow submitting current query even if not in list? 
                // For strict game, maybe only allow from list.
                // Let's assume strict matching for now, or finding best match.
                const bestMatch = filteredOptions[0];
                if (bestMatch && bestMatch.toLowerCase() === query.toLowerCase()) {
                    handleSubmit(bestMatch);
                }
            }
        } else if (e.key === 'Escape') {
            setIsOpen(false);
        }
    };

    return (
        <div className="relative w-full max-w-md mx-auto" ref={wrapperRef}>
            <div className="relative group">
                <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                    <Search className="h-5 w-5 text-zinc-500 group-focus-within:text-primary transition-colors" />
                </div>
                <input
                    ref={inputRef}
                    type="text"
                    className={clsx(
                        "w-full bg-[#1e1e1e] border-2 border-surfaceHighlight text-white pl-10 pr-4 py-3 rounded-xl outline-none transition-all placeholder:text-zinc-600",
                        "focus:border-primary/50 focus:shadow-[0_0_20px_rgba(139,92,246,0.1)]",
                        disabled && "opacity-50 cursor-not-allowed"
                    )}
                    placeholder="Guess the function..."
                    value={query}
                    onChange={(e) => {
                        setQuery(e.target.value);
                        setIsOpen(true);
                        setFocusedIndex(-1);
                    }}
                    onFocus={() => setIsOpen(true)}
                    onKeyDown={handleKeyDown}
                    disabled={disabled}
                    autoComplete="off"
                    autoCorrect="off"
                    spellCheck="false"
                />
            </div>

            <AnimatePresence>
                {isOpen && query && filteredOptions.length > 0 && (
                    <motion.ul
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="absolute z-50 w-full mt-2 bg-[#1e1e1e] border border-surfaceHighlight rounded-xl shadow-xl overflow-hidden"
                    >
                        {filteredOptions.map((option, index) => (
                            <li
                                key={option}
                                className={clsx(
                                    "px-4 py-3 cursor-pointer flex items-center justify-between transition-colors",
                                    index === focusedIndex ? "bg-primary/10 text-primary" : "hover:bg-zinc-800 text-zinc-300"
                                )}
                                onClick={() => handleSubmit(option)}
                                onMouseEnter={() => setFocusedIndex(index)}
                            >
                                <span className="font-mono text-sm">{option}</span>
                                {index === focusedIndex && <Check className="w-4 h-4 opacity-50" />}
                            </li>
                        ))}
                    </motion.ul>
                )}
            </AnimatePresence>
        </div>
    );
}
