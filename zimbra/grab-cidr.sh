#!/bin/bash

export PATH=/usr/bin:/bin:/usr/sbin:/usr/local/bin:$PATH

# Script to update Canada and USA cidr blocks used by blackmiter, etc
# 7/11/2017 - JAD
#
# Note: ipsets incur an additional lookup for each cidr so aggregate
#       works better if he reduce the number of possible cidr masks...
#       ie. /23 is not better as two /24 

# CAVEAT: Fixups exist when the database has errors in it from your source.

#
# from: http://www.ipdeny.com/ipblocks/
#

blackmilter="/usr/local/blackmilter/"

# Step 0 (Choose and create a location to put the files)
cd /home/jad/src/get-country-cidr

# Step 1 (Choose countries you want to include)
prev_can="ca-aggregated.zone"
prev_usa="us-aggregated.zone"
prev_gb="gb-aggregated.zone"
prev_ie="ie-aggregated.zone"

begin_file ()
{
	# If previous run, rename
	if [ -f $1 ]; then
           mv $1 $1.old
	fi
}

cmp_file ()
{
	diff $1 $1.old > /dev/null 2>&1
	return $?
}

# Do we need to rebuild file?
begin_file "$prev_can"
begin_file "$prev_usa"
begin_file "$prev_gb"
begin_file "$prev_ie"

# Step 2 (Choose source of data)
# aggregate (smaller)
wget 'http://www.ipdeny.com/ipblocks/data/aggregated/ca-aggregated.zone'
wget 'http://www.ipdeny.com/ipblocks/data/aggregated/us-aggregated.zone'
wget 'http://www.ipdeny.com/ipblocks/data/aggregated/gb-aggregated.zone'
wget 'http://www.ipdeny.com/ipblocks/data/aggregated/ie-aggregated.zone'
# Another source (every day they pull)
#wget 'http://www.iwik.org/ipcountry/US.cidr' -O us-aggregated.zone
#wget 'http://www.iwik.org/ipcountry/CA.cidr' -O ca-aggregated.zone
#wget 'http://www.iwik.org/ipcountry/GB.cidr' -O gb-aggregated.zone
#wget 'http://www.iwik.org/ipcountry/IE.cidr' -O ie-aggregated.zone

# 
#wget http://www.ipdeny.com/ipblocks/data/countries/us.zone
#wget http://www.ipdeny.com/ipblocks/data/countries/ca.zone

cmp_file "$prev_can"
can=$?
cmp_file "$prev_usa"
usa=$?
cmp_file "$prev_gb"
gb=$?
cmp_file "$prev_ie"
ie=$?

#
fileChanged=$(( $can + $usa + $gb + $ie ))
#fileChanged=1  #for debugging
echo "zone file status (has changed): $fileChanged"

# Do we rebuild the list
if [ $fileChanged -ne 0 ]; then
	if [ -f bl-country ]; then
         /bin/rm -f bl-country
	fi

        # build new list of country cidrs.
	cat $prev_can $prev_usa $prev_gb $prev_ie > bl-country

	# Build list of 8's, 16's, and 24's
	egrep '(/6|/7|/8)' bl-country > A.cidr
	egrep '(/9|/10|/11|/12|/13|/14|/15|/16)' bl-country > B.cidr
	egrep '(/17|/18|/19|/20|/21|/22|/23|/24)' bl-country > C.cidr

	#fix-ups
        echo '65.112.0.0/12' >> B.cidr

	# from: https://github.com/firehol/iprange
	iprange --min-prefix 8 A.cidr > A.class
	iprange --min-prefix 16 B.cidr > B.class
	iprange --min-prefix 24 C.cidr > C.class

        #%%% bug above didn't work so trying it this way
        echo '65.125.131.0/24' >> C.class
        echo '208.75.123.0/24' >> C.class
        echo '204.75.142.0/24' >> C.class
        echo '145.14.134.0/24' >> C.class
        echo '147.75.178.0/24' >> C.class
        echo '147.75.31.0/24' >> C.class
        echo '185.140.204.0/24' >> C.class

	# New file format that Blackmilter can parse better
	cat A.class B.class C.class > bl-country-class
        mv bl-country-class bl-country

	# cleanup
	/bin/rm -f A.class B.class C.class
	/bin/rm -f A.cidr B.cidr C.cidr

	if [ -s bl-country ]; then
          /bin/cp $blackmilter/bl-country $blackmilter/bl-country.old
          echo copying bl-country to $blackmilter/bl-country
          cp bl-country $blackmilter/bl-country
        fi
fi

exit
