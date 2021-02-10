cd ~/
apt install golang -y
apt install git -y
apt install python -y
apt install python2 -y 
pkg install root-repo
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
go get -u -v github.com/tomnomnom/assetfinder
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx
go get -u github.com/tomnomnom/httprobe
GO111MODULE=on go get -u -v github.com/lc/subjs
apt install nmap -y
go get github.com/tomnomnom/waybackurls
go get -u -v github.com/lc/gau
go get -u -v github.com/lukasikic/subzy
git clone https://github.com/projectdiscovery/nuclei-templates
pkg install findomain -y
pkg install nmap -y
go get -u -v github.com/lukasikic/subzy
pkg install jq -y
git clone https://github.com/nahamsec/lazys3
GO111MODULE=on go get -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz
git clone https://github.com/BountyStrike/Injectus
GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...
pkg install wget -y
git clone 
https://github.com/nirsarkar/dirsearch-master
pkg install dnsutils -y
go get -u github.com/tomnomnom/qsreplace
go get github.com/hakluke/hakcheckurl
mkdir $HOME/recondata
mv go/bin/* ~/../usr/bin
pip3 install aiohttp
