import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Terminal, Calendar, Trophy, BookOpen, ArrowRight } from 'lucide-react';
import CodeRain from '../components/layout/CodeRain';

export default function Home() {
    return (
        <div className="relative min-h-[80vh] flex flex-col items-center justify-center overflow-hidden">
            <CodeRain />

            <div className="z-10 flex flex-col items-center space-y-12 w-full max-w-5xl px-4">

                {/* Hero Section */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8 }}
                    className="text-center space-y-6"
                >
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-surfaceHighlight border border-white/10 text-emerald-400 text-sm font-mono mb-4">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                        Daily Challenge Active
                    </div>

                    <h1 className="text-6xl md:text-8xl font-black tracking-tighter text-white">
                        CVERSING
                    </h1>

                    <p className="text-xl md:text-2xl text-zinc-400 max-w-2xl mx-auto leading-relaxed">
                        The daily puzzle for reverse engineers. <br />
                        Can you identify the standard C function from its <span className="text-emerald-400 font-mono">Ghidra pseudo-code</span>?
                    </p>

                    <div className="flex flex-col sm:flex-row gap-4 justify-center pt-8">
                        <Link to="/daily">
                            <button className="group relative px-8 py-4 bg-white text-black font-bold text-lg rounded-xl hover:bg-emerald-400 transition-all shadow-[0_0_20px_rgba(255,255,255,0.3)] hover:shadow-[0_0_30px_rgba(16,185,129,0.5)] flex items-center gap-3">
                                <Calendar className="w-5 h-5" />
                                Play Daily Challenge
                                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                            </button>
                        </Link>
                        <Link to="/infinite">
                            <button className="px-8 py-4 bg-surfaceHighlight text-white font-bold text-lg rounded-xl hover:bg-surface border border-white/10 transition-all flex items-center gap-3">
                                <Trophy className="w-5 h-5 text-amber-400" />
                                Practice Mode
                            </button>
                        </Link>
                    </div>
                </motion.div>

                {/* Features Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full pt-12">
                    {[
                        {
                            title: "Daily Streak",
                            desc: "Solve one function every day to build your reputation.",
                            icon: Calendar,
                            color: "text-blue-400",
                            delay: 0.2
                        },
                        {
                            title: "Real Decompilation",
                            desc: "Code extracted directly from libc using Ghidra.",
                            icon: Terminal,
                            color: "text-purple-400",
                            delay: 0.3
                        },
                        {
                            title: "Wiki Database",
                            desc: "Study the patterns of common C functions.",
                            icon: BookOpen,
                            color: "text-pink-400",
                            delay: 0.4
                        }
                    ].map((feature) => (
                        <motion.div
                            key={feature.title}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: feature.delay, duration: 0.5 }}
                            className="p-6 rounded-2xl bg-surface/50 border border-white/5 hover:border-white/10 transition-colors backdrop-blur-sm"
                        >
                            <feature.icon className={`w-8 h-8 mb-4 ${feature.color}`} />
                            <h3 className="text-lg font-bold text-white mb-2">{feature.title}</h3>
                            <p className="text-zinc-400 text-sm leading-relaxed">{feature.desc}</p>
                        </motion.div>
                    ))}
                </div>
            </div>
        </div>
    );
}
