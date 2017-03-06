import mechanize
import cookielib
import commands
import sys
passtmp=commands.getoutput('/usr/local/bin/makepasswd')
print "Mot de passe: "+passtmp
#sys.exit (0)
# Browser
br = mechanize.Browser()

# Cookie Jar
cj = cookielib.LWPCookieJar()
br.set_cookiejar(cj)

# Browser options
br.set_handle_equiv(True)
br.set_handle_gzip(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)

# Follows refresh 0 but not hangs on refresh > 0
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

# Want debugging messages?
br.set_debug_http(True)
br.set_debug_redirects(True)
br.set_debug_responses(True)


br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615  Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

br.open('https://MY-IP/index.php')


# Show the html title
print br.title()

# Show the response headers
print br.response().info()

# Show the available forms
for f in br.forms():
   print f

# Select the first (index zero) form
br.select_form(nr=0)

# Let's search
br.form["usernamefld"] = "admin"
br.form["passwordfld"] = "!!!MY-PASWORD-ADMIN!!!"

br.submit()
print br.response().read()

br.find_link(text='User Manager')

# Actually clicking the link
req = br.click_link(text='User Manager')
br.open(req)
#print br.response().read()
#print br.geturl()

for l in br.links(url_regex='edit&id=[0-9]+'):
#    print l
    req = br.click_link(l)
    br.open(req)
    admin=0
    for f in br.forms():
        if f["usernamefld"].find("admin") == -1:
            print f 
        else:
            print f
            admin=1
    if admin == 1:
        print "NO ADMIN CHANGE PASSWORD"
    else:
        print "CHANGE PASSWORD"
        br.form["passwordfld1"] = passtmp
        br.form["passwordfld2"] = passtmp
        br.submit()
