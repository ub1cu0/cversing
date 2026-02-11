import { useMemo } from 'react';
import { tokenizeCode } from '../../utils/ghidra-styles';
import { Copy } from 'lucide-react';
import clsx from 'clsx';

interface CodeViewerProps {
    code: string;
    className?: string;
    showLineNumbers?: boolean;
}

export default function CodeViewer({ code, className, showLineNumbers = true }: CodeViewerProps) {
    const tokens = useMemo(() => tokenizeCode(code), [code]);

    // Group tokens by line
    const lines = useMemo(() => {
        const linesArr: { tokens: typeof tokens }[] = [];
        let currentLineTokens: typeof tokens = [];

        tokens.forEach((token) => {
            if (token.text === '\n') {
                linesArr.push({ tokens: currentLineTokens });
                currentLineTokens = [];
            } else {
                currentLineTokens.push(token);
            }
        });
        if (currentLineTokens.length > 0) linesArr.push({ tokens: currentLineTokens });
        return linesArr;
    }, [tokens]);

    const handleCopy = () => {
        navigator.clipboard.writeText(code);
        // Add toast notification logic here if needed
    };

    return (
        <div className={clsx("relative rounded-xl overflow-hidden border border-surfaceHighlight bg-[#1e1e1e] shadow-2xl", className)}>
            {/* Mac-style Window Controls + Actions */}
            <div className="flex items-center justify-between px-4 py-2 bg-[#252526] border-b border-[#333]">
                <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                </div>
                <div className="text-xs text-zinc-500 font-mono">decompiled_function.c</div>
                <button
                    onClick={handleCopy}
                    className="p-1 hover:bg-white/10 rounded transition-colors text-zinc-400 hover:text-white"
                    title="Copy Code"
                >
                    <Copy size={14} />
                </button>
            </div>

            {/* Code Area */}
            <div className="p-4 overflow-x-auto min-h-[300px] max-h-[600px] text-sm font-mono leading-relaxed">
                <table className="w-full border-collapse">
                    <tbody>
                        {lines.map((line, index) => (
                            <tr key={index} className="hover:bg-white/5 transition-colors">
                                {showLineNumbers && (
                                    <td className="w-8 select-none text-right pr-4 text-zinc-600 border-r border-white/5">
                                        {index + 1}
                                    </td>
                                )}
                                <td className="pl-4 whitespace-pre">
                                    {line.tokens.map((token, tIndex) => (
                                        <span key={tIndex} className={token.className}>
                                            {token.text}
                                        </span>
                                    ))}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
