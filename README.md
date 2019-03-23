# blacklistmilter

# Purpose
To reduce the attack surface on your mail server by providing the ability to filter based on geoblocking or geotagging for your spam/malware scoring engine.

# Location of geo files
http://www.ipdeny.com/ipblocks/data/aggregated/

# Operation Summary
We currently use this in tagging (markonly) mode only. A better solution for blocking would be to use ipset.
Add email header to all incoming email that indicates if this is from an ip source that is normal.
Add email header to all incoming email that this ip source has previously attacked this mail server.
Used in Reputation checks later by Spamassassin in scoring

# Operation
The milter tracks various blacklists. We currently use 2 blacklists. The first is for storing ip's of previous attacking MTA. That list is populated by a script in real-time that looks for error messagesin in the logs and updates a blacklist txt file. The second blacklist is all the ip addresses that reside in that Country[s] that is considered normal traffic for your mail server. Anything else is flagged as foreign. In both cases, if the blacklist text files change the milter will automatically reload it's internal database. On delivery to the mail server, Spamassassin will score the headers added to the email. Additionally, a zimbra filter looks for that header and tags email as foreign source should it not be sent to the junk folder. Add countries that are normal for your email mix in Zimbra/grab-cidr.sh ... 

# Storage
The data structure is a hash table, with some enhancement to deal with netmasks/prefixes. Both speed and storage efficient are good.

# Output of grab-cdir.sh
This can be used with ipsets but the primary intention is to build Class A,B,C ranges for the countries you generally get email from (normal)

# History
The original milter was written by Jeff Poskanzer and was the most efficient method I had seen to date in holding large cidr's. This started initially with an earlier release of his milter and was upgraded to the new version that supported ipv6.  The milter supports both blocking and tagging but I describe tagging here (markonly).

Usage (This is started at boot time)
------------------------------------
This milter is tested production ready with sendmail. It should also work with postfix. Here is how to start it:

~~~~
# /usr/local/sbin/blackmilter -markonly -loglistname -autoupdate \
           -blacklist /usr/local/blackmilter/blacklist         \
           -blacklist /usr/local/blackmilter/bl-country        \
           /usr/local/blackmilter/blackmilter.sock
~~~~

This is the entry in your sendmail.mc
-------------------------------------

~~~~
INPUT_MAIL_FILTER(`blackmilter',`S=unix:/usr/local/blackmilter/blackmilter.sock,T=S:4m;R:4m')
~~~~
