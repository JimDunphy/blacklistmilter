# blacklistmilter

# Purpose
To reduce the attack surface of your mail server by providing additional data for your spam/malware scoring engine.

# Operation in a Nutshell
Add email header to all incoming email that indicates if this is from an ip source that is normal.
Add email header to all incoming email that this ip source has previously attacked this mail server.
Used in Reputation checks later by Spamassassin in scoring

# Operation
The milter keeps various blacklists. We currently use 2 blacklists. The first is for storing ip's of previous attacking sites. That list is populated by a script that looks for error messagesin the logs and created a blacklist txt file. The second blacklist is a list of countries that is considered normal traffic for the mail server. Anything else is flagged. In both cases, if the blacklist text files change the milter will automatically reload it's internal database. On delivery to the mail server, Spamassassin will use the headers added to the email for additional scoring. Additionally, a zimbra filter will tag that the email came from a foreign source. Add countries that are normal for your email mix in Zimbra/grab-cidr.sh ... 

# Storage
The data structure is a hast table, with some enhancement to deal with netmasks/prefixes. Both speed and storage efficient are good.

# Output of grab-cdir.sh
This can be used with ipsets but the primary intention is to build Class A,B,C ranges for the countries you deem normal

# History
The milter written by Jeff Poskanzer was the most efficient method I have seen to date in holding large cidr's. This started initially with an earlier release of his milter and was reported to the new version that supports ipv6.  The milter supports both blocking and tagging but we describe tagging here (markonly).

# Usage
This milter is tested production ready with sendmail. It should also work with postfix. Here is how to start it:
/usr/local/sbin/blackmilter -markonly -loglistname -autoupdate -blacklist /usr/local/blackmilter/blacklist -blacklist /usr/local/blackmilter/bl-country /usr/local/blackmilter/blackmilter.sock

This is the entry in your sendmail.mc file

INPUT_MAIL_FILTER(`blackmilter',`S=unix:/usr/local/blackmilter/blackmilter.sock,T=S:4m;R:4m')
