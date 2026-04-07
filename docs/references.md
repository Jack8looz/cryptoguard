## Key reference — LLM cryptographic misuse detection

Firouzi, E., Ghafari, M. (2026). Can generative AI detect and fix
real-world cryptographic misuses? Journal of Systems & Software, 232,
112650. https://doi.org/10.1016/j.jss.2025.112650

Key findings for CryptoGuard:
- GPT-4o with engineered prompt: F1=0.85 on Android, vs CryptoGuard F1=0.80
- Prompt engineering alone improved CAMBench precision from 0.46 to 0.83
- Three prompt techniques: chain-of-thought, multi-misuse detection, name-blindness
- Privacy limitation acknowledged p.14: "industrial projects cannot share
  proprietary source code with external LLM services" — justifies our local model
- Fix accuracy: >93% of suggested fixes were correct
- Chunk size: 10,000 token limit per file for optimal detection
