# NEST-X : HackOps Toolkit

NEST-X is a free, offline cybersecurity toolkit built with Python. It bundles
five learning-focused tools into one workspace: a desktop GUI for the core
utilities and an interactive command-line toolkit for everything.

> For educational and authorised security testing only.

## Tools

| # | Tool | What it does |
|---|------|--------------|
| 1 | Port Scanner | Checks open TCP ports, service names and short risk notes |
| 2 | Password Strength Analyzer | Scores password length/complexity and suggests fixes |
| 3 | Random Password Generator | Creates cryptographically secure passwords with `secrets` |
| 4 | Metadata Extractor | Reads EXIF/GPS/timestamps with ExifTool and calculates MD5, SHA-1 and SHA-256 hashes |
| 5 | Phishing URL Detector | Static, offline heuristics for suspicious links; never opens the URL |

The desktop GUI (`nestx_launcher.py`) covers the first three tools. The
command-line toolkit (`NESTX_Toolkit.py`) includes all five.

## Repository structure

```
Final_CyberToolKit/
├── README.md
├── .gitignore
├── tools/
│   ├── NESTX_Toolkit.py       # five-tool command-line toolkit
│   ├── nestx_launcher.py      # Tkinter desktop GUI (core three tools)
│   ├── exiftool.exe           # bundled ExifTool
│   └── exiftool_files/        # ExifTool runtime files
└── website/
    ├── Website NEST-X.html
    ├── instructions.html
    ├── about.html
    ├── contact.html
    ├── Nest -X logo.jpg
    ├── assets/style.css
    └── downloads/NestX_Toolkit.zip
```

## Requirements

- Python 3.9 or newer
- Tkinter for the desktop GUI (included with the standard Windows installer)
- ExifTool is bundled, so no separate install is needed for metadata analysis

## Run it

From the `tools/` folder:

```bash
python nestx_launcher.py   # GUI
python NESTX_Toolkit.py    # CLI, all five tools
```

Keep `exiftool.exe` and the `exiftool_files` folder next to `NESTX_Toolkit.py`.

## Website

The static site in `website/` can be opened directly in a browser. It links to
the packaged download at `website/downloads/NestX_Toolkit.zip` and works on
GitHub Pages without a build step.

## Privacy

Everything runs locally. Passwords and analysis results are not uploaded or
stored. The only network traffic happens when you explicitly run a port scan
against a target you choose. The phishing detector never visits the URL it
analyzes.

## Safe and ethical use

Only scan systems you own or have explicit written permission to test. Never
use this toolkit to access, damage or disrupt someone else's device or network.
NEST-X is a learning aid, not an attack kit.

## Credits

NEST-X Project Team
St. Vincent Pallotti College of Engineering and Technology
Prof. Neha Zade (Project Guide)

Think Offensively. Defend Ethically. Build Securely. 🔐
