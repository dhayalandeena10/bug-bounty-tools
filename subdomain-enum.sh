if [[ -z $1 ]]; then
    echo "you have not specified any target"
else
FILE=/root/recondata/$1
if [ -d "$FILE" ]; then
    echo "$1 already done RECON!!."
else
mkdir /$HOME/recondata/$1
cd /$HOME/recondata/$1
python3 ~/Sublist3r/sublist3r.py -d $1 -o $1-sublister.txt
subfinder -d $1 -all -o $1-sf
assetfinder --subs-only $1 | sort -u >> $1-af
findomain --quiet -t $1 -u $1-fd
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
curl -v -silent https://$1 --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u |tee -a csp.txt
#using rapiddns
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> $1.txt
#using jldc
curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> $1.txt
#using bufferover 
curl -s https://dns.bufferover.run/dns?q=.$1 |jq -r .FDNS_A[] | sed -s 's/,/\n/g' |grep [a-z] >> $1.txt
#amass enum -active -d $1.active.txt
cd ~/Sudomy/
bash /root/Sudomy/sudomy -d $1 --no-probe -o $1
cd /$HOME/recondata/$1
crobat -s $1 |sort -u|tee -a $1-crobat
python3 /root/ctfr/ctfr.py -d $1 -o $1-ctfr.txt
cat * |grep '\.$1$'|sort -u|tee passive.txt
#python3 ~/dnsrecon/dnsrecon.py -d $1 -a -s -y -b -k -c $1-dns.txt
if [[ "$(dig @1.1.1.1 A,CNAME {test321123,testingforwildcard,plsdontgimmearesult}.$1 +short | wc -l)" -gt "1" ]]; then
    echo "[!] Possible wildcard detected, skipping subdomain bruteforce"
else
    #puredns bruteforce ~/wordlists/all-in-one-subdomains.txt $1 -r ~/resolvers.txt -w $1
    gotator -sub passive.txt -perm ~/wordlist/gotator.txt -depth 1 -numbers 10 -mindup -adv -md -silent >> gotator.txt
    puredns resolve gotator.txt -r ~/resolvers.txt -w gotator-subs
fi
#subdomains from dnsx
#cat $1-dns.txt | grep $1|cut -d , -f2|sort -u|grep '\.$1$'|sort -u|tee -a $1-dns
cat $1-sublister.txt $1-ctfr.txt $1.txt passive.txt $1-sf $1-af $1-fd $1-crobat csp.txt /root/Sudomy/$1/Sudomy-Output/$1/subdomain.txt crt.txt | grep -F ".$1" | sed 's/\*\.//g' |sort -u >> passive.txt
cat $1|anew passive.txt > brutesubs
rm -r  $1-sublister.txt /root/Sudomy/$1 $1-ctfr.txt $1.txt $1-sf $1-af $1-fd $1-crobat csp.txt $1 crt.txt
#cat $1.txt $1-sf $1 $1 findomain.txt crt.txt | grep -F ".$1" | sed 's/\*\.//g' |sort -u >> passive.txt 
dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -silent -l passive.txt| cut -d '[' -f2 | sed 's/.$//' | egrep ".$1$"|sort -u |anew passive.txt
cat passive.txt  | httpx -follow-host-redirects -status-code -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew web_full_info.txt | cut -d ' ' -f1 | grep ".$1$" | anew -q probed_tmp_scrap.txt
cat probed_tmp_scrap.txt | httpx -tls-grab -tls-probe -csp-probe -status-code -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew web_full_info.txt | cut -d ' ' -f1 | grep ".$1$" | anew probed_tmp_scrap.txt | unfurl -u domains |grep '\.$1$' |anew -q passive.txt
gospider -S probed_tmp_scrap.txt --js -t 4 -d 3 --sitemap --robots -w -r > gospider.txt
cat gospider.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".$1$" | anew -q passive.txt
cat probed_tmp_scrap.txt | analyticsrelationships >> analytics_subs_tmp.txt
cat analytics_subs_tmp.txt | grep "\.$1$\|^$1$" | sed "s/|__ //" | anew -q passive.txt
rm analytics_subs_tmp.txt probed_tmp_scrap.txt gospider.txt
cat passive.txt  | httpx -follow-host-redirects -status-code -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew web_full_info.txt | cut -d ' ' -f1 | grep ".$1$" | anew -q probed_tmp_scrap.txt
cat probed_tmp_scrap.txt | httpx -tls-grab -tls-probe -csp-probe -status-code -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew web_full_info.txt | cut -d ' ' -f1 | grep ".$1$" | anew probed_tmp_scrap.txt | unfurl -u domains |grep '\.$1$' |anew -q passive.txt
gospider -S probed_tmp_scrap.txt --js -t 4 -d 3 --sitemap --robots -w -r > gospider.txt
cat gospider.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".$1$" | anew -q passive.txt
cat probed_tmp_scrap.txt | analyticsrelationships >> analytics_subs_tmp.txt
cat analytics_subs_tmp.txt | grep "\.$1$\|^$1$" | sed "s/|__ //" | anew -q passive.txt
rm analytics_subs_tmp.txt probed_tmp_scrap.txt gospider.txt
cat passive.txt  | httpx -follow-host-redirects -status-code -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew web_full_info.txt | cut -d ' ' -f1 | grep ".$1$" | anew -q probed_tmp_scrap.txt
cat probed_tmp_scrap.txt | httpx -tls-grab -tls-probe -csp-probe -status-code -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew web_full_info.txt | cut -d ' ' -f1 | grep ".$1$" | anew probed_tmp_scrap.txt | unfurl -u domains |grep '\.$1$' |anew -q passive.txt
gospider -S probed_tmp_scrap.txt --js -t 4 -d 3 --sitemap --robots -w -r > gospider.txt
cat gospider.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".$1$" | anew -q passive.txt
cat probed_tmp_scrap.txt | analyticsrelationships >> analytics_subs_tmp.txt
cat analytics_subs_tmp.txt | grep "\.$1$\|^$1$" | sed "s/|__ //" | anew -q passive.txt
rm analytics_subs_tmp.txt probed_tmp_scrap.txt gospider.txt
dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -silent -l passive.txt| cut -d '[' -f2 | sed 's/.$//' | egrep ".$1$"|sort -u |anew passive.txt
cat passive.txt |httprobe|anew http.txt
gospider -S http.txt --js -t 4 -d 3 --sitemap --robots -w -r > gospider.txt
cat gospider.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//'|grep ".$1"|anew urls.txt
getjs --complete --input urls.txt --insecure --output js-files
getjs --complete --input js-files --insecure --output js-files-2
cat js-files js-files-2|unfurl -u domains| grep ".$1$" | anew -q passive.txt
rm js-files js-files-2
cat passive.txt |httprobe|anew http.txt
gospider -S http.txt --js -t 4 -d 3 --sitemap --robots -w -r > gospider.txt
cat gospider.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//'|grep ".$1"|anew urls.txt
getjs --complete --input urls.txt --insecure --output js-files
getjs --complete --input js-files --insecure --output js-files-2
cat js-files js-files-2|unfurl -u domains| grep ".$1$" | anew -q passive.txt
cat passive.txt|gau |grep -E '\.js' |grep -ivE '\.json'|grep -v '\.jsp'|sort -u|anew js-files-gau
cat passive.txt|waybackurls |grep -E '\.js' |grep -ivE '\.json'|grep -v '\.jsp'|sort -u|anew js-files-wayback
cat js-files-gau js-files-wayback |sort -u|anew js-files.txt
rm js-files-gau js-files-wayback
cat js-files.txt |unfurl -u domains|grep '\.$1$'|anew passive.txt > new-domains
gospider -S new-domains --js -t 4 -d 3 --sitemap --robots -w -r > gospider.txt
cat gospider.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//'|grep ".$1"|anew urls.txt
cat new-domains|gau|grep -E '\.js' |grep -ivE '\.json'|grep -v '\.jsp'|sort -u|anew js-files-gau
cat new-domains|waybackurls |grep -E '\.js' |grep -ivE '\.json'|grep -v '\.jsp'|sort -u|anew js-files-wayback
cat js-files-gau jsfiles-wayback |sort -u|anew js-files.txt
rm js-files-gau js-files-wayback
#httprobe all the domains
rm http.txt
cat gotator-subs|anew passive.txt
rm gotator-subs gotator.txt
findomain -f passive.txt -u second-run-fd
subfinder -dL passive.txt -o second-run-sf
cat second-run-* |anew passive.txt
rm second-run-*
#gotator -sub passive.txt -perm ~/wordlist/gotator.txt -depth 1 -numbers 10 -mindup -adv -md -silent >> goatator.txt
cat passive.txt|httprobe |anew http.txt
cat passive.txt |naabu -rate 5000 -v -exclude-ports 80,443 -o ports.txt -p -
cat ports.txt |httprobe|anew http.txt
cat http.txt |nuclei -t ~/nuclei-templates/ -o nuclei.txt
source ~/.bash_aliases
cat passive.txt|gau|grep -v '\.js'|grep -v '\.css'|grep -v '\.png'|grep -v '\.img'|anew gau-urls
cat passive.txt|waybackurls|grep -v '\.js'|grep -v '\.css'|grep -v '\.png'|grep -v '\.img'|anew wayback-urls

#cat http.txt |while read hosts;do ffuf_quick $hosts;done
#cat http.txt |httpx -title |sort -k 2,2 -u|awk '{print $1}'|tee fuzz-urls
#cat http.txt |while read hosts;do ffuf_dotfiles $hosts;done
#cat http.txt |while read hosts;do arjun_quick $hosts;done
#cat fuzz-urls |while read hosts;do ffuf_recursive $hosts;done
fi
fi
