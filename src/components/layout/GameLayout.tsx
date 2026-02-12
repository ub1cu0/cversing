import type { ReactNode } from 'react';
import { Trophy, Calendar, Sparkles, Terminal } from 'lucide-react';
// @ts-ignore
import { Link, useLocation } from 'react-router-dom';
import clsx from 'clsx';

interface GameLayoutProps {
    children: ReactNode;
}

export default function GameLayout({ children }: GameLayoutProps) {
    const location = useLocation();

    const navItems = [
        { path: '/daily', label: 'Daily', icon: Calendar },
        { path: '/infinite', label: 'Infinite', icon: Trophy },
        { path: '/wiki', label: 'Wiki', icon: Sparkles },
    ];

    return (
        <div className="min-h-screen bg-background text-zinc-100 font-sans selection:bg-primary/30">
            {/* Header */}
            <header className="border-b border-surfaceHighlight bg-surface/50 backdrop-blur-md sticky top-0 z-50">
                <div className="max-w-5xl mx-auto px-4 h-16 flex items-center justify-between">
                    <Link to="/" className="flex items-center gap-2 group decoration-none">
                        <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center group-hover:bg-primary/20 transition-colors">
                            <Terminal className="w-5 h-5 text-primary" />
                        </div>
                        <span className="font-bold text-lg tracking-tight bg-gradient-to-br from-white to-zinc-400 bg-clip-text text-transparent">
                            Cversing
                        </span>
                    </Link>

                    <nav className="flex items-center gap-1">
                        {navItems.map((item) => {
                            const isActive = location.pathname.startsWith(item.path);
                            const Icon = item.icon;
                            return (
                                <Link
                                    key={item.path}
                                    to={item.path}
                                    className={clsx(
                                        "flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 decoration-none",
                                        isActive
                                            ? "bg-surfaceHighlight text-white"
                                            : "text-zinc-400 hover:text-zinc-200 hover:bg-surfaceHighlight/50"
                                    )}
                                >
                                    <Icon className="w-4 h-4" />
                                    {item.label}
                                </Link>
                            );
                        })}
                    </nav>
                </div>
            </header>

            {/* Main Content */}
            <main className="max-w-5xl mx-auto px-4 py-8 min-h-[calc(100vh-8rem)]">
                {children}
            </main>

            {/* Footer */}
            <footer className="border-t border-surfaceHighlight py-6 text-center text-sm text-zinc-500">
                <p>© {new Date().getFullYear()} Cversing. Built for reversing practice.</p>
            </footer>
        </div>
    );
}
