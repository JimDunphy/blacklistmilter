# blacklistmilter

# Purpose
To reduce the attack surface on your mail server by providing the ability to filter based on geoblocking or geotagging for your spam/malware scoring engine.

# Location of geo files
http://www.ipdeny.com/ipblocks/data/aggregated/

# Operation Summary
The milter is configured in tagging (markonly) mode only. A better solution for blocking would be to use ipset with the data from grab-cidr.sh but it is possible to block foreign addresses with the milter. The milter will add an email header to all incoming email that indicates if this is from an ip source that is normal for the type of countries you generally have email correspondance with.  An additional email header is added to all incoming email for ip addresses that has previously attacked this mail server.  We use these headers in Reputation checks later by Spamassassin in scoring. We also will send to syslog the initial SMTP HELO/EHLO statement for real-time watching of connection, ip addresses, and arguments. We use swatch to monitor this output.

# Operation
The milter tracks various blacklists. We currently use 2 blacklists but more are possible. The first blacklist is for storing ip's of previous attacking MTA's. That list is populated by a script in real-time that looks for error messages in the logs and updates a blacklist txt file. The second blacklist is all the ip addresses that reside in Country[s] that is considered normal traffic for your mail server. Anything else is flagged as foreign. In both cases, if the blacklist text files change the milter will automatically reload it's internal database. On delivery to the mail server, Spamassassin will score the headers added to the email. Additionally, a zimbra filter looks for that header and tags email as foreign source should it not be sent to the junk folder. Add countries that are normal for your email mix in Zimbra/grab-cidr.sh ... 

# Storage
The data structure is a hash table, with some enhancement to deal with netmasks/prefixes. Both speed and storage efficient are good.

# Layout
There is a zimbra directory with support files to build the data that is used in the blacklists. The blacklists are txt files that contain cidr's or ip addresses. 

# Output of grab-cdir.sh
This can be used with ipsets but the primary intention is to build Class A,B,C ranges for the countries you generally get email from (normal)

# History
The original milter was written by Jeff Poskanzer and was the most efficient method I had seen to date in holding large cidr's. This started initially with an earlier release of his milter and was upgraded to the new version that supported ipv6.  The milter supports both blocking and tagging but I describe tagging here (markonly).

# Production Ready
We have run this 24/7/365 for the past 5 years. It has never failed. More information about blackmilter can be found here:
http://www.acme.com/software/blackmilter/

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
