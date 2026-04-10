# Scenario 2 – Brute-Force Login Attack

## Description
Detects brute-force or password-spraying attacks against authentication services such as
Windows login, SSH, RDP, or web applications.

## Attack Technique
- **MITRE ATT&CK**: T1110 – Brute Force (including T1110.001 Password Guessing, T1110.003 Password Spraying)

## Indicators of Compromise
- Multiple failed login attempts (> 5 within 1 minute) from the same source IP
- Failed logins spread across many accounts from a single source (password spray)
- Successful login immediately following a burst of failures
- Logins from unusual geographies or IP ranges

## Detection Rule
See `../queries/login-detection-rule.txt` for the corresponding SIEM query.

## Response Steps
1. Block the offending source IP at the firewall / WAF.
2. Temporarily lock out the targeted accounts if a compromise is suspected.
3. Review authentication logs for any successful logins after the failure burst.
4. Reset credentials for any account that successfully authenticated during the attack window.
5. Notify the account owner and document the incident.

## References
- https://attack.mitre.org/techniques/T1110/
