"""Shared detection pattern definitions.

Provides a single source of truth for pattern lists used by different
heuristic detectors to avoid duplication and drift across modules.
"""

# HeuristicDetector patterns (string regex, confidence, description)

HEURISTIC_DIRECT_INJECTION_PATTERNS: list[tuple[str, float, str]] = [
    # Instruction override attempts
    (r"ignore (all )?(previous|prior|above|instructions?)", 0.9, "Instruction override attempt"),
    (
        r"disregard (all )?(previous|prior|above|your training|instructions?)",
        0.9,
        "Instruction override attempt",
    ),
    (r"forget (everything|all|what)", 0.85, "Memory reset attempt"),
    (r"new instructions?:?", 0.8, "New instruction injection"),
    (r"update.{0,20}(instruction|directive|command)", 0.8, "Instruction update attempt"),
    # Role play and impersonation
    (r"(you are|you're) (now |going to be |a )", 0.85, "Role manipulation"),
    (r"act (as|like) (a|an)", 0.8, "Role playing request"),
    (r"pretend (to be|you)", 0.85, "Impersonation attempt"),
    (r"roleplay as", 0.85, "Role playing request"),
    # Safety bypass statements
    (
        r"(I will|I'll) (now |)ignore (all |)(safety|rules|restrictions)",
        0.9,
        "Safety bypass statement",
    ),
    (
        r"ignore (all |)(safety|security) (rules|restrictions|guidelines)",
        0.9,
        "Safety bypass attempt",
    ),
    # Role confusion attacks
    (r"^(System|Assistant|User|Admin):", 0.8, "Role label injection"),
    (r"<<(SYSTEM|ADMIN|ROOT)>>", 0.85, "Special role delimiter"),
    (r"Role:\s*(admin|root|system)", 0.85, "Role escalation attempt"),
    (r"Access:\s*(granted|allowed|unrestricted)", 0.8, "Access control bypass"),
    (r"(I'm|I am) (the|an) (assistant|system|admin)", 0.85, "Role reversal attempt"),
    (r"(you're|you are) (the|a) (user|human)", 0.85, "Role reversal attempt"),
    # System prompt extraction
    (
        r"(what|tell me|show me).{0,20}(system|initial|original) (prompt|instruction)",
        0.9,
        "System prompt extraction attempt",
    ),
    (r"repeat.{0,20}(instruction|prompt|directive|everything|above)", 0.85, "Prompt leak attempt"),
    (
        r"(print|output|display|show).{0,20}(above|previous|prior|initial|original)",
        0.8,
        "Content extraction",
    ),
    (
        r"(print|output|display).{0,20}(your|the).{0,20}(instruction|configuration)",
        0.85,
        "Config extraction",
    ),
    (r"what were you told", 0.8, "Prompt extraction attempt"),
    (
        r"(tell|show|give).{0,20}(me|us).{0,20}(your|the).{0,20}instruction",
        0.85,
        "Instruction extraction",
    ),
    (r"verbatim", 0.7, "Verbatim output request"),
    # Command injection style
    (r"<\|.*\|>", 0.9, "Special delimiter injection"),
    (r"\[\[.*\]\]", 0.7, "Bracket command injection"),
    (r"{{.*}}", 0.7, "Template injection"),
    (r"execute:?", 0.8, "Command execution attempt"),
    (r"\[\[CONTEXT_SWITCH\]\]", 0.9, "Context switch command"),
    # SQL injection patterns
    (r"(drop|delete|truncate|alter)\s+(table|database)", 0.95, "SQL injection attempt"),
    (r"';|--;|/\*|\*/|union\s+select", 0.9, "SQL injection syntax"),
    (r"or\s+1\s*=\s*1|and\s+1\s*=\s*0", 0.85, "SQL injection condition"),
    # Code injection patterns
    (r"import\s+(os|sys|subprocess)", 0.85, "System module import"),
    (r"(eval|exec|compile)\s*\(", 0.9, "Code execution attempt"),
    (r"__import__|globals\(\)|locals\(\)", 0.85, "Dynamic code execution"),
    (r"subprocess\.(run|call|Popen)", 0.9, "Process execution attempt"),
    (r"System\.(set|get)SecurityManager", 0.9, "Security manager manipulation"),
    (r"```[\s\S]*```", 0.6, "Code block injection attempt"),
]

HEURISTIC_JAILBREAK_PATTERNS: list[tuple[str, float, str]] = [
    (r"(DAN mode|dan mode|activate dan|enable dan)", 0.95, "DAN jailbreak attempt"),
    (r"developer mode", 0.9, "Developer mode jailbreak"),
    (
        r"(unlock|enable|activate).{0,20}(hidden|secret|advanced|feature)",
        0.85,
        "Feature unlock attempt",
    ),
    (r"sudo\s+", 0.8, "Privilege escalation attempt"),
    (r"(admin|administrator)\s+(mode|access|privileges?)", 0.85, "Admin access attempt"),
    (r"bypass.{0,20}(restriction|filter|safety)", 0.9, "Bypass attempt"),
    (
        r"(from now on|going forward).{0,20}(you will|respond as|act as)",
        0.85,
        "Role override attempt",
    ),
    (r"(STAN|GPT-4|claude|llama|alpaca|vicuna)", 0.8, "Model impersonation attempt"),
    (r"pretend (you are|to be)", 0.85, "Pretend instruction"),
]

HEURISTIC_ENCODING_PATTERNS: list[tuple[str, float, str]] = [
    (r"[A-Za-z0-9+/]{20,}={0,2}$", 0.7, "Potential base64 encoding"),
    (r"\\x[0-9a-fA-F]{2}", 0.8, "Hex encoding detected"),
    (r"\\u[0-9a-fA-F]{4}", 0.8, "Unicode encoding detected"),
    (r"(%[0-9a-fA-F]{2}){3,}", 0.7, "URL encoding detected"),
    (r"&(#x?[0-9a-fA-F]+|[a-z]+);", 0.6, "HTML entity encoding"),
]

HEURISTIC_CONTEXT_SWITCHING_PATTERNS: list[tuple[str, float, str]] = [
    (r"###.{0,20}(system|user|assistant)", 0.8, "Role delimiter injection"),
    (r"(end of|close) (conversation|chat|session)", 0.7, "Context termination attempt"),
    (r"(start|begin) (new|another) (conversation|session)", 0.7, "Context reset attempt"),
    (r"\n{3,}", 0.5, "Excessive newlines for context break"),
    (r"={10,}", 0.6, "Separator injection"),
    (r"---END OF.{0,20}---", 0.8, "Context boundary injection"),
    (r"</user>[\s\S]*<system>", 0.9, "XML tag injection"),
    (r"</(user|assistant|human)>", 0.8, "XML closing tag injection"),
]


# OptimizedHeuristicDetector pattern definitions by category

OPTIMIZED_PATTERN_DEFINITIONS: dict[str, list[tuple[str, float, str]]] = {
    "injection": [
        (r"ignore (all )?(previous|prior|above)", 0.9, "Instruction override"),
        (r"disregard (all )?(previous|prior|above|your training)", 0.9, "Instruction override"),
        (r"forget (everything|all|previous)", 0.85, "Memory manipulation"),
        (r"new (instructions?|commands?|rules?):", 0.8, "New instruction injection"),
        (r"(you are|you're) now", 0.75, "Role manipulation"),
        (r"act as if you (are|were)", 0.75, "Role manipulation"),
        (r"pretend (you are|to be)", 0.7, "Role pretending"),
        (r"from now on", 0.7, "Context switching"),
    ],
    "jailbreak": [
        (r"(DAN|dan) mode", 0.95, "DAN jailbreak"),
        (r"developer mode", 0.9, "Developer mode attempt"),
        (r"(disable|bypass|ignore) (safety|filters?|restrictions?)", 0.9, "Safety bypass"),
        (r"unlimited power", 0.85, "Unrestricted mode"),
        (r"no (restrictions?|limits?|rules?)", 0.8, "Restriction removal"),
    ],
    "data_extraction": [
        (
            r"(show|reveal|display) (your )?(system )?(prompt|instructions?)",
            0.9,
            "System prompt extraction",
        ),
        (r"what are your (instructions?|rules?|guidelines?)", 0.85, "Instruction fishing"),
        (r"repeat (your |the )?(first|initial|original)", 0.8, "Context extraction"),
        (r"(list|show) all (your )?capabilities", 0.75, "Capability enumeration"),
    ],
    "encoding": [
        (r"base64|base32|hex|binary", 0.7, "Encoding detected"),
        (r"rot13|caesar|cipher", 0.75, "Cipher detected"),
        (r"[A-Za-z0-9+/]{50,}={0,2}", 0.6, "Possible base64"),
    ],
}
