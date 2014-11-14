ActiveAuth_Perl
===============

**ActiveAuth_perl** - two-factor authentication for Perl web applications

This package allows a web developer to add ActiveAuths's two-factor authentication to any web login form.

Package:

* `js` - ActiveAuth javascript library, to be hosted by your webserver.
* `ActiveAuth.pm` - ActiveAuth Perl SDK to be integrated with your web application

# Usage

## 1. Generate Application key:

Your application key (or akey) is a string that you should generate and keep secret from ActiveAuth. It should be 40 characters long and stored alongside your integration key, secret key, integration account and integration server in configuration.

You can generate a random string in Perl with:

```
perl -e 'print join "", map { sprintf "%08X", rand(0xffffffff) } 1 .. 5'
```

## 2. Sign your request

After you perform primary authentication (username and password), you should prepare signature for the secondary authentication process by calling `ActiveAut::sign` method:

```
my $secret = ActiveAuth::sign($username, $ikey, $skey, $akey);
```

Where:

* `$username` is the e-mail of already the first-step-authenticated account
* `$ikey` is the integration key you get from ActiveAuth's control panel
* `$skey` is the server key you get from ActiveAuth's control panel
* `$akey` which is the application key you generated