# Authorization Policy

BLACKJARVIS runs only against:

1. **Systems I own** (home lab, my VMs, Raspberry Pi targets)
2. **Intentionally vulnerable training platforms** — TryHackMe, HackTheBox,
   PortSwigger Web Security Academy, OverTheWire, etc.
3. **Bug bounty programs** where I am a registered participant, against assets
   **explicitly listed as in-scope** in the program brief.

## Hard rules

- Out-of-scope domains MUST be hard-blocked at the tool wrapper level
- Production systems of any organization without explicit written authorization are never targeted
- API rate limits and program rules are respected
- All findings are reported via proper channels (program submission forms),
  not blogged about or publicly disclosed prematurely

I take full responsibility for ensuring authorization before running any scan,
probe, or exploit against any system.
