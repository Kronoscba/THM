# Security notice

This repository is for educational purposes only. Do NOT store sensitive files such as .vpn, .pem, .key or .secret here. If you need a VPN configuration, keep it on an isolated machine and never commit it.

## Recommended structure
src/
docs/
README.md

## Best practices
1. Do not version any secret files.
2. Use .gitignore to exclude patterns like *.vpn.
3. Review history (git log -p) or use tools like GitLeaks before pushing.
4. If you accidentally pushed secrets, remove history with git filter-repo or the BFG.

## Contact
Author: Your Name
Channel: Course Slack/Telegram

---
This project is licensed under MIT. See LICENSE for details.
