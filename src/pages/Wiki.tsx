import { useState } from 'react';
import { functionsData } from '../utils/dataSource';
import CodeViewer from '../components/game/CodeViewer';
import { Search, BookOpen, ChevronDown, ChevronUp } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function Wiki() {
    const [search, setSearch] = useState('');
    const [expandedId, setExpandedId] = useState<string | null>(null);

    const filtered = functionsData.filter(f =>
        f.name.toLowerCase().includes(search.toLowerCase()) ||
        f.description.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <div className="max-w-4xl mx-auto space-y-8">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <h2 className="text-2xl font-bold flex items-center gap-2">
                    <BookOpen className="text-emerald-400" />
                    Function Wiki
                </h2>
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 w-4 h-4" />
                    <input
                        type="text"
                        placeholder="Search functions..."
                        className="pl-9 pr-4 py-2 bg-surfaceHighlight border border-white/5 rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-400 w-full md:w-64"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                    />
                </div>
            </div>

            <div className="grid gap-4">
                {filtered.map(func => (
                    <div key={func.id} className="bg-surface border border-surfaceHighlight rounded-xl overflow-hidden shadow-sm hover:border-zinc-700 transition-colors">
                        <button
                            onClick={() => setExpandedId(expandedId === func.id ? null : func.id)}
                            className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-white/5 transition-colors"
                        >
                            <div>
                                <h3 className="font-mono font-bold text-lg text-primary">{func.name}</h3>
                                <p className="text-zinc-400 text-sm">{func.description}</p>
                            </div>
                            {expandedId === func.id ? <ChevronUp className="text-zinc-500" /> : <ChevronDown className="text-zinc-500" />}
                        </button>

                        <AnimatePresence>
                            {expandedId === func.id && (
                                <motion.div
                                    initial={{ height: 0 }}
                                    animate={{ height: 'auto' }}
                                    exit={{ height: 0 }}
                                    className="overflow-hidden border-t border-surfaceHighlight bg-[#1e1e1e]"
                                >
                                    <div className="p-4">
                                        <CodeViewer code={func.code} showLineNumbers={false} className="border-0 shadow-none" />
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                ))}

                {filtered.length === 0 && (
                    <div className="text-center py-20 text-zinc-500">
                        No functions found matching "{search}"
                    </div>
                )}
            </div>
        </div>
    );
}
