# Show HN: Anthropic charges $15/PR for code review. I built a locally-evolving alternative that found 18 bugs for $0.004.

**Title:** Show HN: Anthropic charges $15/PR for code review. I built a locally-evolving alternative that found 18 bugs for $0.004.

---

Recently, Anthropic launched an expensive $15–$25 per PR code review tool, triggering massive developer backlash. To solve this, I built `lore-review`, which just produced 18 real findings on a live PR — including a ReDoS vulnerability in `_normalize_error_msg` and an O(n²) bottleneck — for exactly $0.004. It uses 4 parallel AI workers (security, performance, correctness, style) dispatched to ultra-cheap models for $0.001/task.

But the real thing isn't the cost. It's the memory: a "Darwin" learning loop clusters failure patterns and automatically generates static deny rules submitted as GitHub PRs. Once a human approves the PR, the entire fleet becomes permanently immune to that codebase-specific mistake. PR 50 is smarter than PR 1. Every other tool resets to zero.

```python
# One-line install
pip install lore-review

# GitHub Action  
uses: Miles0sage/lore-review@main

# What it found on a real phalanx PR:
# [HIGH]   security     ReDoS in _normalize_error_msg regex pattern
# [HIGH]   performance  O(n²) in _extract_common_prefixes nested loop  
# [MEDIUM] security     User-controlled data in regex processing → hash
# [MEDIUM] correctness  Single-action path returns [] breaking intent
# ... 14 more findings
# Total cost: $0.0040
```

**What it is:** 4 parallel AI council workers + Darwin per-codebase learning. MIT license. Works as a GitHub Action or CLI. Zero dependencies for core.

**What it isn't:** A real-time guardrail. Darwin runs offline. Rules are static and human-approved before enforcement — 100% auditable for SOC2.

**What's early-stage:** The graph-based context (code-review-graph integration) is in fallback mode. Darwin needs 2+ similar findings before it generates rules — first reviews are council-only.

**The meta-story:** I ran lore-review on the PR that added Darwin's security hardening. It found a ReDoS in the security fix. That's the point.

- GitHub: https://github.com/Miles0sage/lore-review
- phalanx (the fleet learning layer): https://github.com/Miles0sage/phalanx

---

# Twitter/X Thread

**Tweet 1:**
CodeRabbit charges $24/mo. Anthropic wants $15–$25 per PR.

I just ran lore-review on a live PR. It found 18 real vulnerabilities (including a ReDoS in regex and an O(n²) algorithm) using 4 parallel AI workers.

Total cost? $0.004. Here's how I built it 🧵

**Tweet 2:**
The $0.004 cost: abandon expensive monolithic models for routine checks.

lore-review dispatches security/style/correctness/performance to Alibaba Qwen at $0.001/task, running in parallel.

But cheap isn't the moat.

**Tweet 3:**
The real moat is memory.

If developers make the same mistake twice, Darwin kicks in. It clusters failures offline and auto-generates a static policy rule submitted as a GitHub PR.

Your codebase builds an immune system.

**Tweet 4:**
The meta-story: I ran lore-review on the PR that added Darwin's security hardening.

It found a ReDoS vulnerability IN the security fix.

That's the point.

**Tweet 5:**
pip install lore-review
uses: Miles0sage/lore-review@main

MIT. GitHub Action. $0.004/PR.

github.com/Miles0sage/lore-review
