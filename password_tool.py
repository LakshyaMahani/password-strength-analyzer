#!/usr/bin/env python3
# (See canvas for full commented source)
from __future__ import annotations
import argparse
import itertools
from pathlib import Path
from typing import Iterable, List, Set

try:
    from zxcvbn import zxcvbn
except Exception:
    zxcvbn = None

LEET_MAP = {'a':['a','@','4'],'e':['e','3'],'i':['i','1','!'],'o':['o','0'],'s':['s','5','$'],'t':['t','7']}
COMMON_SUFFIXES = ['!','@','#','1','12','123','1234','2020','2021','2022','2023','2024','2025','.','*','!','00']
SEPARATORS = ['', '.', '-', '_']

def entropy_from_score(score:int)->float:
    return {0:0.0,1:10.0,2:28.0,3:40.0,4:60.0}.get(int(score),0.0)

def analyze_password(pwd:str, user_inputs:List[str]|None=None)->dict:
    if zxcvbn is None:
        raise SystemExit("zxcvbn is not installed. Install with: pip install zxcvbn")
    res = zxcvbn(pwd, user_inputs=user_inputs or [])
    return {
        'password': pwd,
        'score': res.get('score'),
        'crack_times': res.get('crack_times_display'),
        'feedback': res.get('feedback'),
        'entropy_estimate_bits': entropy_from_score(res.get('score',0)),
    }

def case_variants(word:str)->Set[str]:
    return {w for w in {word, word.lower(), word.upper(), word.capitalize(), word.title()} if w}

def leet_variants(word:str, enable:bool)->Set[str]:
    if not enable: return {word}
    choices = [LEET_MAP.get(ch.lower(), [ch]) for ch in word]
    return {''.join(p) for p in itertools.product(*choices)}

def append_years(words:Iterable[str], years:Iterable[str])->Set[str]:
    out=set()
    for w in words:
        out.add(w)
        for y in years: out.add(f"{w}{y}")
    return out

def add_suffixes(words:Iterable[str], suffixes:Iterable[str])->Set[str]:
    out=set()
    for w in words:
        out.add(w)
        for s in suffixes: out.add(f"{w}{s}")
    return out

def combine_tokens(tokens:List[str], max_tokens_per_combo:int, separators:List[str])->Set[str]:
    combos=set()
    tokens=[t for t in tokens if t]
    for r in range(1, min(len(tokens), max_tokens_per_combo)+1):
        for perm in itertools.permutations(tokens, r):
            for sep in separators: combos.add(sep.join(perm))
    return combos

def re_split_keep_digits(text:str)->List[str]:
    out=[]; buf=''; last=None
    for ch in text:
        cur=ch.isdigit()
        if last is None: buf=ch; last=cur; continue
        if cur==last: buf+=ch
        else: out.append(buf); buf=ch; last=cur
    if buf: out.append(buf)
    return out

def write_lines(path:Path, lines:Iterable[str])->None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for line in lines: f.write(f"{line}\n")

def generate_wordlist(raw_inputs:List[str], years:List[str], include_leet:bool, include_case:bool,
                      include_suffixes:bool, separators:List[str], max_tokens_per_combo:int, max_words:int)->List[str]:
    base=set()
    for item in raw_inputs:
        if not item: continue
        item=str(item).strip(); base.add(item)
        base.update([p for p in re_split_keep_digits(item) if p])
    expanded=set()
    for tok in base:
        cvars = {tok} if not include_case else {tok, tok.lower(), tok.upper(), tok.capitalize(), tok.title()}
        for cv in cvars: expanded.update(leet_variants(cv, include_leet))
    combined = combine_tokens(sorted(expanded), max_tokens_per_combo, separators)
    with_years = append_years(combined, years) if years else combined
    final_set = add_suffixes(with_years, COMMON_SUFFIXES) if include_suffixes else with_years
    words = sorted(final_set, key=lambda x:(len(x), x))
    if max_words>0: words = words[:max_words]
    return words

def main():
    p = argparse.ArgumentParser(description="Password Strength Analyzer + Custom Wordlist Generator",
                                formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument('--analyze', action='store_true')
    p.add_argument('--password', type=str)
    p.add_argument('--batch-passwords', type=Path)
    p.add_argument('--user-inputs', nargs='*', default=[])
    p.add_argument('--save-analysis', type=Path)
    p.add_argument('--generate', action='store_true')
    p.add_argument('--inputs', nargs='*', default=[])
    p.add_argument('--years', nargs='*', default=[])
    p.add_argument('--leet', action='store_true')
    p.add_argument('--case', action='store_true')
    p.add_argument('--suffixes', action='store_true')
    p.add_argument('--seps', nargs='*', default=['', '.', '-', '_'])
    p.add_argument('--max-combo', type=int, default=3)
    p.add_argument('--max-words', type=int, default=50000)
    p.add_argument('--out', type=Path)
    args = p.parse_args()

    did=False

    if args.analyze:
        did=True
        pw_list=[]
        if args.password: pw_list.append(args.password)
        if args.batch_passwords and args.batch_passwords.exists():
            with args.batch_passwords.open('r', encoding='utf-8') as f:
                pw_list.extend([line.strip() for line in f if line.strip()])
        if not pw_list: p.error("--analyze requires --password or --batch-passwords")
        reports=[analyze_password(pw, args.user_inputs) for pw in pw_list]
        for r in reports:
            print("\n=== Analysis ===")
            print(f"Password: {r['password']}")
            print(f"Score (0–4): {r['score']} | Entropy ~{r['entropy_estimate_bits']} bits")
            ct=r['crack_times'] or {}
            print("Crack times (est.):")
            for k,v in ct.items(): print(f"  - {k}: {v}")
            fb=r['feedback'] or {}
            if fb.get('warning'): print(f"Warning: {fb['warning']}")
            if fb.get('suggestions'):
                print("Suggestions:")
                for s in fb['suggestions']: print(f"  - {s}")
        if args.save_analysis:
            lines=[]
            for r in reports:
                lines.append("=== Analysis ===")
                lines.append(f"Password: {r['password']}")
                lines.append(f"Score (0–4): {r['score']} | Entropy ~{r['entropy_estimate_bits']} bits")
                ct=r['crack_times'] or {}
                lines.append("Crack times (est.):")
                for k,v in ct.items(): lines.append(f"  - {k}: {v}")
                fb=r['feedback'] or {}
                if fb.get('warning'): lines.append(f"Warning: {fb['warning']}")
                if fb.get('suggestions'):
                    lines.append("Suggestions:")
                    for s in fb['suggestions']: lines.append(f"  - {s}")
                lines.append("")
            write_lines(args.save_analysis, lines)
            print(f"Saved analysis to {args.save_analysis}")

    if args.generate:
        did=True
        words = generate_wordlist(args.inputs, args.years, args.leet, args.case, args.suffixes,
                                  args.seps, max(1,int(args.max_combo)), max(0,int(args.max_words)))
        if args.out: write_lines(args.out, words); print(f"Generated {len(words)} words -> {args.out}")
        else: print("\n".join(words))

    if not did: p.print_help()

if __name__ == "__main__":
    main()
