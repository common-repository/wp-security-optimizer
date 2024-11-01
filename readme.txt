=== WP Security Optimizer ===

Author: Luca Ercoli
Author URI: http://www.lucaercoli.it/
Contributors: lucaercoli
Tags: block user agent, wpscan, xml-rpc, hackers, spam
Plugin Name: WP Security Optimizer
Plugin URI:  https://www.wp-security-optimizer.com/
Requires at least: 3.5
Tested up to: 4.9.8
Stable tag: 1.5.15
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Donate link: https://paypal.me/lucaercoliit/5

Protect your site from vulnerability scanner and hackers




== Description ==

Prevent hackers to sabotage your rankings in search engines.

Elude attackers that exploits your website and fight Negative SEO attacks made using WPScan and other vulnerability scanner.

An inspection engine monitors the traffic between clients and your Website, enhancing the security of your WordPress installation.

WP Security Optimizer prevents wp-login brute force attacks by monitoring invalid login attempts, block dDoS attack via pingbacks, XMLRPC attack and is able to elude vulnerability scanners;
Specially designed for WPScan where it's able to induce false-positives and generate an unreadable report full of thousand wrong data.

File Integrity Check (FIC) functionality will notify the administrative user about corrupted and infected PHP files stored into "wp-admin", "wp-includes" and "uploads" folders.

Analyzing the User-Agent field in the HTTP request headers, disallow access on your Website to the most widespread penetration test and security assessment applications, including: OpenVAS, Nikto, sqlmap, commix, skipfish, whatweb and WPScan.

Useful for finding files that are actually used by developers (such of backup of Wordpress's configuration), page accessible but unlinked and README files that expose version number and reveal potential vulnerabilities. 

WP Security Optimizer is able to recognize common probing patterns used to look for vulnerabilities in WordPress, sending security notifications to the email address of blog administrator.

The one thing you should do is activate it using the built-in plugin manager of WordPress. WP Security Optimizer does not require any configuration. Just install it!




== Installation ==

=== From within WordPress ===

1. Login to your weblog
1. Go to Plugins
1. Select Add New
1. Search for 'WP Security Optimizer'
1. Select Install Now
1. Activate WP Security Optimizer from your Plugins page.

=== Manually ===

1. Download and unzip the plugin
1. Upload the entire "wp-security-optimizer" directory to the /wp-content/plugins/ directory
1. Activate the plugin through the Plugins menu in WordPress




== Screenshots ==

1. WP Security Optimizer can block username enumeration made with security assessment toolkit like WPScan
2. Smart features like "Scan Avoidance Technology" ensures false-positives in security scanner that analyze your site
3. WP Security Optimizer will protect you from plugin discovery attack 
4. Stay secure against hackers that use themes discovery techniques on your Wordpress installation
5. Flooding hacker with fake reply, WP Security Optimizer will temporary hang WPScan client
6. WPScan protection: hacker will obtain an unreadable report with 20700+ wrong data
7. Control Center administration page and menu
8. File Integrity Check (FIC) functionality



== Changelog ==

= 1.5.15 =

* Tweak: Wordpress signatures updated

= 1.5.14 =

* Tweak: Wordpress signatures updated

= 1.5.13 =

* Tweak: WPScan signatures updated

= 1.5.12 =

* Tweak: WPScan signatures updated

= 1.5.11 =

* Tweak: WPScan signatures updated
* Add: Donation feature

= 1.5.10 =

* Tweak: File Integrity Check signatures updated

= 1.5.9 =

* Tweak: File Integrity Check signatures updated

= 1.5.8 =

* Tweak: File Integrity Check signatures updated

= 1.5.7 =

* Tweak: Reporting system has been improved
* Tweak: File Integrity Check signatures updated

= 1.5.6 =

* Tweak: File Integrity Check signatures updated

= 1.5.5 =

* Add: File Integrity Check (FIC) functionality search for PHP scripts saved into "uploads" folder
* Tweak: Reporting graphs implemented  

= 1.5.4 =

* Add: Switchable email alerting settings on WPScan detection
* Tweak: Directory listing protection enhanced

= 1.5.3 =

* Add: Support for HTTP and HTTPS upstream proxies for brute force attacks. The X-Forwarded-For request header help you to identify the real client IP address

= 1.5.2 =

* Add: File Integrity Check (FIC): A critical functionality for Wordpress security. The administrative user will be notified about corrupted and infected PHP files stored into "wp-admin" and "wp-includes" folders

= 1.5.1 =

* Add: Filter for WhatWeb's default User-Agent

= 1.5.0 =

* Add: Prevents brute force attacks by monitoring invalid login attempts
* Add: Notifications by email on brute force attacks
* Add: Attacks Reporting Section in Control Center menu

= 1.4.0 =

* Add: Block brute force and dDoS attack via XML-RPC

= 1.3.2 =

* Tweak: Hide its 'readme' file preventing to expose own version number

= 1.3.1 =

* Fix: Fixed logo image path in Control Center menu

= 1.3 =

* Add: Control Center administration page and menu

= 1.2 =

* Add: E-mail notifications has now geolocation support to trace hacker's IP

= 1.1 =

* Tweak: Does not replace "X-Meta-Generator" header for admin users

= 1.0 =

* First public release
