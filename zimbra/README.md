# Requirements for grab-cidr.sh 
git clone https://github.com/firehol/iprange
cd iprange
./autogen.sh
./configure --disable-man
make
make install
