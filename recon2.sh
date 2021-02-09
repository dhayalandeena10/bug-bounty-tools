rm -rf /$HOME/recondata/$1
mkdir /$HOME/recondata/$1
cd /$HOME/recondata/$1
subfinder -d $1 -all -o subfinder.txt
assetfinder --subs-only $1 | sort -u > assetfinder.txt
findomain --quiet -t $1 -u findomain.txt 
#usingcrt.sh at defferent levels
curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.%.%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.%.%.%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.%.%.%.%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.%.%.%.%.%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
curl -s https://crt.sh/?Identity=%.%.%.%.%.%.%.%.%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' > crt.txt
#using certspotter
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> $1.txt
#using rapiddns
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> $1.txt
#using jldc
curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> $1.txt
#using bufferover 
curl -s https://dns.bufferover.run/dns?q=.$1 |jq -r .FDNS_A[] | sed -s 's/,/\n/g' |grep [a-z] >> $1.txt
amass enum --passive -d $1 -o amass.txt
cat $1.txt amass.txt subfinder.txt assetfinder.txt findomain.txt crt.txt | grep -F ".$1" | sed 's/\*\.//g' |sort -u > passive.txt 
rm -rf $1.txt subfinder.txt assetfinder.txt findomain.txt crt.txt amass.txt

#starting httprobe
cat passive.txt | httprobe >> http.txt
#starting nuclei scan.
nuclei -update-templates
#cat http.txt | nuclei -t /$HOME/nuclei-templates/ | tee nuclei.txt

#getting all the available extensions.
gau -subs $1 | egrep -i -E -o "\.{1}\w*$" | sort -su | tee ext

#starting crlfuzz
echo "started crlf injector"
#crlfuzz -l http.txt -s | tee crlf.txt

#starting subzy
subzy -targets passive.txt -hide_fails | tee subvulns.txt

#open redirect testing
python3 /$HOME/Injectus/Injectus.py -f http.txt -op | tee openredirect.txt

#scanning all the open ports.
cat http.txt |grep -oP 'https://\K\S+'| sort -u >> nmap.txt
nmap -iL nmap.txt -T5 | tee ports.txt

