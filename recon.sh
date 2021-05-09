if [[ -z $1 ]]
then
echo "you have not specified any target"
else
rm -rf /$HOME/recondata/$1
mkdir /$HOME/recondata/$1
cd /$HOME/recondata/$1
subfinder -d $1 -all -o subfinder.txt
assetfinder --subs-only $1 | sort -u >> assetfinder.txt
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
~/puredns/./puredns bruteforce ~/puredns/subdomains $1 -w $1
cat $1.txt amass.txt subfinder.txt assetfinder.txt ~/puredns/$1 findomain.txt crt.txt | grep -F ".$1" | sed 's/\*\.//g' |sort -u >> passive.txt 
rm $1.txt subfinder.txt assetfinder.txt ~/puredns/$1 findomain.txt crt.txt amass.txt

#starting httprobe
cat passive.txt | httprobe >> http.txt
#starting nuclei scan.
nuclei -update-templates
cat http.txt | nuclei -t /$HOME/nuclei-templates/ | tee nuclei.txt

#starting subzy
subzy -targets passive.txt -hide_fails | tee subvulns.txt

#staring robots files enumeration.
cat http.txt >> hosts
echo "/robots.txt" >> paths
meg --verbose -s 200 paths hosts
cat out/*/* | grep -i disallow | awk '{print $2}' | sort -u | tee robotspath.txt

#starting gau and hakrawler
cat passive.txt |hakrawler -robots| tee roboturls.txt
cat passive.txt |hakrawler -urls | awk '{print $2}' |tee urls.txt
echo "started gau........"
cat passive.txt |gau -subs |sort -u |tee -a urls.txt
fi
