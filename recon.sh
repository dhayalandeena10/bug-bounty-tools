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
#getting subs from csp
#curl -v -silent https://$1 --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u |tee -a assetfinder.txt
#using rapiddns
#curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> $1.txt
#using jldc
#curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> $1.txt
#using bufferover 
#curl -s https://dns.bufferover.run/dns?q=.$1 |jq -r .FDNS_A[] | sed -s 's/,/\n/g' |grep [a-z] >> $1.txt
#amass enum -active -d $1.active.txt
crobat -s $1 |sort -u|tee -a $1.txt
amass enum --passive -d $1 -o amass.txt
#<<<<<<< HEAD
puredns bruteforce ~/wordlists/2m-subdomains.txt $1 -r ~/resolvers.txt -w $1
cat $1.txt amass.txt subfinder.txt $1.active.txt assetfinder.txt findomain.txt crt.txt | grep -F ".$1" | sed 's/\*\.//g' |sort -u >> passive.txt 
cat $1|anew passive.txt > brutesubs
rm $1.txt subfinder.txt assetfinder.txt $1 $1.active.txt findomain.txt crt.txt amass.txt
#=======
puredns bruteforce ~/2m-subdomains.txt $1 -w $1
cat $1.txt amass.txt subfinder.txt assetfinder.txt $1 findomain.txt crt.txt | grep -F ".$1" | sed 's/\*\.//g' |sort -u >> passive.txt 
#rm $1.txt subfinder.txt assetfinder.txt $1 findomain.txt crt.txt amass.txt
#>>>>>> 39a900d215f6f3419bd4ba4e5fcaa047b99ca9a5

naabu -iL passive.txt -rate 5000 -exclude-ports 80,443 -o ports
#starting httprobe
cat passive.txt ports| httprobe >> http.txt
#starting nuclei scan.
nuclei -update-templates
cat http.txt | nuclei -t /$HOME/nuclei-templates/ | tee nuclei.txt
cat nuclei.txt | grep -i 'low' |notify
cat nuclei.txt | grep -i 'medium' |notify
cat nuclei.txt | grep -i 'high' |notify
cat nuclei.txt | grep -i 'critical' |notify

#starting subzy
subzy -targets passive.txt -hide_fails | tee subvulns.txt
echo "gau runnig..."
cat http.txt |gau|sort -u|tee gau.txt
cat gau|grep = |sort -u|kxss|tee kxss.txt
#cat passive.txt | while read hosts;do (bash ~/xssauto/QuickXSS.sh -d $hosts -b https://deena.xss.ht);done
#cat http.txt |httpx -silent -follow-redirects -mc 200 |aquatone 
#cat ~/xssauto/results/*/results.txt |notify
#staring robots files enumeration.
#cat http.txt >> hosts
#echo "/robots.txt" >> paths
#meg --verbose -s 200 paths hosts
#cat out/*/* | grep -i disallow | awk '{print $2}' | sort -u | tee robotspath.txt

#starting gau and hakrawler
#cat passive.txt |hakrawler -robots| tee roboturls.txt
#cat passive.txt |hakrawler -urls | awk '{print $2}' |tee urls.txt
#echo "started gau........"
#cat passive.txt |gau -subs |sort -u |tee -a urls.txt
fi
