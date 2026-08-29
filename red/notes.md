# THM Red - Session Notes

## Target
- IP: 10.64.146.176
- THM Room: Red (Red vs Blue classic)

## Defense Mechanisms (from room description)
1. Red kicks adversaries out of the machine — session cycling/termination
2. Red changes adversaries' passwords but keeps them relatively similar — predictable password pattern
3. Red taunts adversaries — likely messages/files left to distract

## Strategy
- Need persistence that survives a kick mechanism
- Need to read messages/files Red leaves to stay focused
- Need to find user accounts, observe password change pattern, predict next password

## Workflow
- Recon -> foothold -> user -> system
- For Red vs Blue style rooms, expect a vulnerable app with a kick mechanism (often a cron resetting)
- THM "Red" is typically based on a vulnerable service with a "kick" routine that kills attacker processes / sessions periodically

## Hypothesis
The classic THM "Red" room is a Linux box where Red periodically resets the attacker (kills shells/forces logout) and rotates passwords. The taunts are left in files. Win = read final flag despite the defenses.

## Steps
1. Nmap scan
2. Enumerate exposed services
3. Find foothold
4. Survive the kick
5. Track password rotations
6. Privilege escalation