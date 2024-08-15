<h1 align="center">
TLDFinder
<br>
</h1>


<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/tldfinder"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/tldfinder"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/tldfinder/pkg/tldfinder"><img src="https://img.shields.io/badge/go-reference-blue"></a>
<a href="https://github.com/projectdiscovery/tldfinder/releases"><img src="https://img.shields.io/github/release/projectdiscovery/tldfinder"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-tldfinder">Running tldfinder</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


A streamlined tool for discovering TLDs, associated domains, and related domain names.

# Features

![image](https://github.com/user-attachments/assets/d9548c6c-7a99-4ba9-8b08-ad716712c645)

 - TLD based DNS lookups (Passive)
 - Reverse domain lookup (Passive)
 - STD **IN/OUT** and **TXT/JSON** output


## Installation

tldfinder requires **Go 1.21** to install successfully. To install, just run the below command or download pre-compiled binary from [release page](https://github.com/projectdiscovery/tldfinder/releases).

```console
go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest
```

## Usage

```console
tldfinder -h
```

This will display help for the tool. Here are all the switches it supports.

```console
tldfinder is a tls data gathering and analysis toolkit.

A streamlined tool for discovering TLDs, associated subdomains, and related domain names.

Usage:
  ./tldfinder [flags]

Flags:
INPUT:
   -d, -domain string[]  domain or list of domains for discovery (file or comma separated)

SOURCE:
   -s, -sources string[]           specific sources to use for discovery (-s censys,dnsrepo). Use -ls to display all available sources.
   -es, -exclude-sources string[]  sources to exclude from enumeration (-es censys,dnsrepo)
   -dm, -discovery-mode value      discovery mode (dns,tld,domain) (default dns)
   -all                            use all sources for enumeration (slow)

FILTER:
   -m, -match string[]   domain or list of domain to match (file or comma separated)
   -f, -filter string[]   domain or list of domain to filter (file or comma separated)

RATE-LIMIT:
   -rl, -rate-limit int      maximum number of http requests to send per second (global)
   -rls, -rate-limits value  maximum number of http requests to send per second four providers in key=value format (-rls hackertarget=10/m) (default ["waybackarchive=15/m", "whoisxmlapi=50/s", "whoisxmlapi=30/s"])
   -t int                    number of concurrent goroutines for resolving (-active only) (default 10)

UPDATE:
   -up, -update                 update tldfinder to latest version
   -duc, -disable-update-check  disable automatic tldfinder update check

OUTPUT:
   -o, -output string       file to write output to
   -oJ, -json               write output in JSONL(ines) format
   -oD, -output-dir string  directory to write output (-dL only)
   -cs, -collect-sources    include all sources in the output (-json only)
   -oI, -ip                 include host IP in output (-active only)

CONFIGURATION:
   -config string                flag config file (default "/Users/user/Library/Application Support/tldfinder/config.yaml")
   -pc, -provider-config string  provider config file (default "/Users/user/Library/Application Support/tldfinder/provider-config.yaml")
   -r string[]                   comma separated list of resolvers to use
   -rL, -rlist string            file containing list of resolvers to use
   -nW, -active                  display active domains only
   -proxy string                 http proxy to use with tldfinder
   -ei, -exclude-ip              exclude IPs from the list of domains

DEBUG:
   -silent             show only domains in output
   -version            show version of tldfinder
   -v                  show verbose output
   -nc, -no-color      disable color in output
   -ls, -list-sources  list all available sources
   -stats              report source statistics

OPTIMIZATION:
   -timeout int   seconds to wait before timing out (default 30)
   -max-time int  minutes to wait for enumeration results (default 10)
```

## Running tldfinder

### Input for tldfinder

**tldfinder** requires **domain** or tld as input for any discovery mode.

```bash
io # TLD input
google.io # Domain input (tld will be auto extracted from domain name)
```

Input can be provided using `-domain / -d` flag, and multiple values can be provided using comma-separated input.

Example run:

```console
$ tldfinder -d google.goog
 ________   ___  _____         __       
/_  __/ /  / _ \/ __(_)__  ___/ /__ ____
 / / / /__/ // / _// / _ \/ _  / -_) __/
/_/ /____/____/_/ /_/_//_/\_,_/\__/_/ 

      projectdiscovery.io

[INF] Enumerating sub(domains) for "goog" TLD
simulations.endpoints.ingka-cff-simulations-prod.cloud.goog
kf1.endpoints.x-delivery-benchmarking.cloud.goog
banquedeprojets-mcinet-gov-ma.translate.goog
www-pietervreedeplein-nl.translate.goog
www.chwsimpreprod.goog
kubeflow-ver1-2.endpoints.dbce-dswb-sbx-e07f.cloud.goog
app2.r1.testacq.mesaintegrationtesting.off.goog
rcs-nightly.staging.telephony.goog
bookstore.endpoints.pergamon-test-apis.cloud.goog
texaspokerfans.endpoints.diamondonline-dev.cloud.goog
pinterest-com.translate.goog
ext.audit.endpoints.mw-project-ext-179e.cloud.goog
mas-provider-dev-co.endpoints.txd-mas-dev.cloud.goog
ca8ru178nqhhk3h75qn0.us-central1.visionai.goog
cbd0d2028lo7e2iocmdg.us-central1.visionai.goog
1p-na-telecom.rcs.telephony.goog
.....
[INF] Found 3329 domains for goog in 10 seconds 458 milliseconds
```

## Acknowledgements

- [N7WEra](https://github.com/N7WEra) for coming up with idea for this project.

--------

<div align="center">

tldfinder is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>
