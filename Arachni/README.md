# Arachni 
## Version 1.4 - patch.diff
## Patch for multi combination on query param
### Actualy arachni test on exemp.com/?parm1=x&param2=y:

parm1=x&param2=VULN

parm1=VULN&param2=y

### Patch extend to:

parm1=x&param2=VULN

parm1=VULN&param2=y

parm1=VULN

param2=VULN

## Version 2.0 - date 25/09/2016 - arachni.patch
url dowload: http://downloads.arachni-scanner.com/nightlies/

Add simhash
  * run arachni_shell and enter "gem install simhash" & exit console
  * edit arachni.gemspec and add in block "Gem::Specification.new do |s|" -> "s.add_dependency 'simhash'"
  * edit Gemfile in system/gems/bundler/gems/arachni-ID/Gemfile, add gem "simhash"
  * edit Gemfile in system/arachni-ui-web/Gemfile, add gem "simhash"

### ADD
  * Overflow_timing: check active, test overflow on params, form, header and verify time_out response
  * search_base64: grep base64 in header, form
  * html_comment: grep comment in html body
  * interesting_timeout: find response server time-out
  * access_control: check if access control is work with another cookie (cookies in cookie.txt current dir)

### MODIFIED
  * rfi: change test on remote site internet by possibility connect on local network with tool netcat
  * mutation: change mutation on param (same in 1.4)
  * header: add header test mutation by list (headers.db)
  
#Contact
@ lionel.prat9 (at) gmail.com Ou cronos56 (at) yahoo.com
#Greetz
Thanks to Tasos Laskos
