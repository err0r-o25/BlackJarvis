# 🤖 BLACKJARVIS

> A local AI assistant for security research and bug bounty automation. Runs entirely on your machine — no cloud, no API keys, no data leaving your laptop.

## 🎯 Status

**Phase 1: Foundation** ✅
- Local LLM via Ollama (qwen2.5:3b on GTX 1650 Ti)
- Python 3.14 + uv project structure
- GitHub repo + SSH auth

**Phase 2: Core functionality** 🚧
- LLM client with tool-calling
- First recon tool wrapper (subfinder)
- Engagement note-taking

**Phase 3: The assistant experience** 🔮
- Voice input (wake word + Whisper STT)
- Voice output (Piper TTS)
- Persistent memory + RAG

## 🧰 Stack

- **OS**: Arch Linux + BlackArch repos
- **Hardware**: ASUS TUF F15, GTX 1650 Ti (4GB VRAM)
- **LLM Runtime**: Ollama (local, GPU-accelerated)
- **Default Model**: `qwen2.5:3b`
- **Language**: Python 3.14 with `uv`
- **Recon Tools**: ProjectDiscovery suite (subfinder, httpx, nuclei, ...)

## 🚀 Quickstart

```bash
git clone git@github.com:err0r-o25/BlackJarvis.git
cd BlackJarvis
uv sync
uv run blackjarvis hello
```

## 📜 Ethics

This tool is for authorized security testing only. See [SCOPE.md](SCOPE.md).

## 📄 License

MIT
