# Changelog

## v1.1.7

* Added option to hide banner
* Added option to save API keys
* Added option to specify custom export directory
* Added option to read API keys from env directly
* More sources added for subdomain enumeration :
    * BinaryEdge
    * Netlas
    * Hunter.How
    * ZoomEye
    * UrlScan
    * AlienVault
* SSL info module optimized
* Fixed TLDExtract issue with IP targets
* Replaced dnslib with dnspython
* Removed psycopg2

---

## v1.1.6

* dependencies reduced
* logger added
* adjusted for new tldextract version
* bevigil added for sub-domain enum
* refactored
* sonar sub-domain query disabled
* improved exception handling in dns enum

---

## v1.1.5

* fixed some url issues in crawler
* threads added in port scanner
* fixed status code issue in directory enumeration module
* more sources added for subdomain enumeration
    * wayback
    * sonar
    * hackertarget

---

## v1.1.4

* CHANGELOG.md added
* export
    * output format changed
    * csv and xml export removed
* subdomain enum
    * bufferover removed
    * shodan integrated
* directory enum
    * module optimized
    * results are printed as they are found
* port scanner
    * module optimized
* dedicated wayback module added