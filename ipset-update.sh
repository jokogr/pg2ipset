#!/usr/bin/env bash

# ipset-update.sh (C) 2012-2015 Matt Parnell http://www.mattparnell.com
# Licensed under the GNU-GPLv2+

# place to keep our cached blocklists
LISTDIR="/var/cache/blocklists"

# countries to block, must be lcase
COUNTRIES=(af ae ir iq tr cn sa sy ru ua hk id kz kw ly)

# bluetack lists to use - they now obfuscate these so get them from
# https://www.iblocklist.com/lists.php
BLUETACKALIAS=(DShield Bogon Hijacked DROP ForumSpam WebExploit Ads Proxies BadSpiders CruzIT Zeus Palevo Malicious Malcode Adservers)
BLUETACK=(xpbqleszmajjesnzddhv lujdnbasfaaixitgmxpp usrcshglbiilevmyfhse zbdlwrqkabxbcppvrnos ficutxiwawokxlcyoeye ghlzqtqxnzctvvajwwag dgxtneitpuvgqqcpfulq xoebmbyexwuiogmbyprb mcvxsnihddgutbjfbghy czvaehmjpsnwwttrdoyl ynkdjqsjyfmilsgbogqf erqajhwrxiuvjxqrrwfj npkuuhuxcsllnhoamkvm pbqcylkejciyhmwttify zhogegszwduurnvsyhdf)
# ports to block tor users from
PORTS=(80 443 6667 22 21)

# remove old countries list
[ -f $LISTDIR/countries.txt ] && rm $LISTDIR/countries.txt

# remove the old tor node list
[ -f $LISTDIR/tor.txt ] && rm $LISTDIR/tor.txt

# enable bluetack lists?
ENABLE_BLUETACK=1

# enable country blocks?
ENABLE_COUNTRY=0

# enable tor blocks?
ENABLE_TORBLOCK=1

chain_exists () {
  [ $# -lt 1 -o $# -gt 2 ] && {
    echo "Usage: chain_exists <chain_name> [table]" >&2
        return 1
  }
  local chain_name="$1" ; shift
  [ $# -eq 1 ] && local table="--table $1"
  iptables $table -n --list "$chain_name" >/dev/null 2>&1
}

importList(){
  if [ -f $LISTDIR/$1.txt ] || [ -f $LISTDIR/$1.gz ]; then
	echo "Importing $1 blocks..."

	ipset create -exist $1 hash:net maxelem 4294967295
	ipset create -exist $1-TMP hash:net maxelem 4294967295
	ipset flush $1-TMP &> /dev/null

	#the second param determines if we need to use zcat or not
	if [ $2 = 1 ]; then
		zcat $LISTDIR/$1.gz | grep  -v \# | grep -v ^$ | grep -v 127\.0\.0 | pg2ipset - - $1-TMP | ipset restore
	else
		awk '!x[$0]++' $LISTDIR/$1.txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ $1\-TMP\ /" | ipset restore
	fi

	ipset swap $1 $1-TMP &> /dev/null
	ipset destroy $1-TMP &> /dev/null

	# only create chains and rules if they do not exist
  if ! iptables -C pg-in -m set --match-set "$1" src -j DROP >/dev/null 2>&1; then
    chain_exists pg-in || iptables -N pg-in
    iptables -A pg-in -m set --match-set $1 src -j NFLOG --nflog-prefix "PG blocked input $1"
    iptables -A pg-in -m set --match-set $1 src -j DROP

    chain_exists pg-fwd || iptables -N pg-fwd
    iptables -A pg-fwd -m set --match-set $1 src -j NFLOG --nflog-prefix "PG blocked fwd $1"
    iptables -A pg-fwd -m set --match-set $1 src -j DROP
    iptables -A pg-fwd -m set --match-set $1 dst -j NFLOG --nflog-prefix "PG blocked fwd $1"

    chain_exists pg-out || iptables -N pg-out
    iptables -A pg-out -m set --match-set $1 dst -j NFLOG --nflog-prefix "PG blocked out $1"
    iptables -A pg-out -m set --match-set $1 dst -j REJECT
	fi
  else
	echo "List $1.txt does not exist."
  fi
}

# create the list directory
mkdir -p $LISTDIR
[[ $? -ne 0 ]] && exit 1

# check if the list directory is writable
if [ ! -w "$LISTDIR" ]; then
  echo "LISTDIR $LISTDIR is not writable" 1>&2
  exit 1
fi

if [ $ENABLE_BLUETACK = 1 ]; then
  # get, parse, and import the bluetack lists
  # they are special in that they are gz compressed and require
  # pg2ipset to be inserted
  i=0
  for list in ${BLUETACK[@]}; do
	if [ eval $(wget --quiet -O /tmp/${BLUETACKALIAS[i]}.gz http://list.iblocklist.com/?list=$list&fileformat=p2p&archiveformat=gz) ]; then
	  mv /tmp/${BLUETACKALIAS[i]}.gz $LISTDIR/${BLUETACKALIAS[i]}.gz
	else
	  echo "Using cached list for ${BLUETACKALIAS[i]}."
	fi

	echo "Importing bluetack list ${BLUETACKALIAS[i]}..."

	importList ${BLUETACKALIAS[i]} 1

	i=$((i+1))
  done
fi

if [ $ENABLE_COUNTRY = 1 ]; then
  # get the country lists and cat them into a single file
  for country in ${COUNTRIES[@]}; do
	if [ eval $(wget --quiet -O /tmp/$country.txt http://www.ipdeny.com/ipblocks/data/countries/$country.zone) ]; then
	  cat /tmp/$country.txt >> $LISTDIR/countries.txt
	  rm /tmp/$country.txt
	fi
  done

  importList "countries" 0
fi


if [ $ENABLE_TORBLOCK = 1 ]; then
  # get the tor lists and cat them into a single file
  for ip in $(ip -4 -o addr | awk '!/^[0-9]*: ?lo|link\/ether/ {gsub("/", " "); print $4}'); do
	for port in ${PORTS[@]}; do
	  if [ eval $(wget --quiet -O /tmp/$port.txt https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip&port=$port) ]; then
		cat /tmp/$port.txt >> $LISTDIR/tor.txt
		rm /tmp/$port.txt
	  fi
	done
  done

  importList "tor" 0
fi

# add any custom import lists below, e.g.
# importTextList "custom"

