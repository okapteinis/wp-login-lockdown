=== Login LockDown ===
Contributors: okapteinis, timotheemoulin, michaelvandemer
Tags: security, login, brute force, login protection, security plugin, login attempts, IP blocking
Requires at least: 5.0
Tested up to: 6.7
Stable tag: 2.1.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress site from brute force login attacks by limiting login attempts from IP addresses.

== Description ==

Login LockDown is a security plugin that protects your WordPress site from brute force login attacks by recording the IP address and timestamp of every failed login attempt.

If more than a certain number of login attempts are detected within a short period of time from the same IP range, the login function is disabled for all requests from that range. This helps prevent automated password discovery attacks.

= Key Features =

* **Automatic IP Blocking** - Blocks IP addresses after multiple failed login attempts
* **Customizable Thresholds** - Configure max retries, lockout duration, and time period
* **IP Range Blocking** - Blocks entire IP ranges to prevent distributed attacks
* **IPv4 and IPv6 Support** - Full support for both IPv4 and IPv6 addresses
* **Manual IP Release** - Administrators can manually release locked IP addresses
* **Activity Logging** - View all failed login attempts and lockouts
* **Multisite Compatible** - Works with WordPress Multisite installations
* **Login Error Masking** - Option to hide specific error messages from attackers
* **Invalid Username Lockout** - Option to lock out attempts with non-existent usernames

= Default Settings =

* **Max Login Retries:** 3 attempts
* **Retry Time Period:** 5 minutes
* **Lockout Duration:** 60 minutes

These can be customized from the Settings panel.

= Security Features in v2.1.0 =

This version includes critical security fixes:

* Fixed SQL injection vulnerabilities in database queries
* Fixed critical IPv6 validation logic error
* Improved input sanitization throughout
* Full PHP 8.4 compatibility with strict type checking
* Enhanced IP address validation

== Installation ==

= Automatic Installation =

1. Log in to your WordPress admin panel
2. Go to Plugins → Add New
3. Search for "Login LockDown"
4. Click "Install Now" and then "Activate"

= Manual Installation =

1. Download the plugin zip file
2. Extract it to your `/wp-content/plugins/` directory
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Configure settings from Settings → Login LockDown

== Frequently Asked Questions ==

= How does Login LockDown protect my site? =

Login LockDown tracks failed login attempts by IP address. When an IP exceeds the allowed number of failed attempts within the specified time period, that IP is temporarily blocked from accessing the login page, preventing automated brute force attacks.

= What happens if I get locked out? =

If you have access to your hosting control panel or FTP, you can:
1. Access your database via phpMyAdmin
2. Find the `wp_login_fails` and `wp_lockdowns` tables
3. Delete the entries for your IP address

Alternatively, contact your hosting provider for assistance.

= Can I whitelist my IP address? =

Currently, the plugin doesn't have a built-in whitelist feature. However, you can manually release your IP from the admin panel if you get locked out.

= Does this work with IPv6? =

Yes! Version 2.1.0 includes improved IPv6 support with proper validation.

= Is this compatible with other security plugins? =

Yes, Login LockDown works alongside most other security plugins. However, if you're using multiple plugins that modify login behavior, test thoroughly to ensure they work together correctly.

= Does this work with Multisite? =

Yes, Login LockDown is fully compatible with WordPress Multisite installations.

= What are the PHP requirements? =

* Minimum: PHP 7.4
* Recommended: PHP 8.0 or higher
* Tested up to: PHP 8.4

== Screenshots ==

1. Settings page - Configure lockdown thresholds and behavior
2. Failed login attempts log - View all failed login attempts
3. Locked out IP addresses - Manage and release locked IPs

== Changelog ==

= 2.1.0 (2025-10-31) =
**CRITICAL SECURITY UPDATE - Immediate update recommended**

**Security Fixes:**
* Fixed critical SQL injection vulnerability in loginlockdown_increment_fails()
* Fixed critical SQL injection vulnerability in loginlockdown_lock_username()
* Fixed SQL string interpolation in table check query
* Fixed critical IPv6 validation logic error causing infinite recursion

**PHP 8.4 Compatibility:**
* Replaced all loose comparisons (==, !=) with strict comparisons (===, !==) - 30+ instances
* Added comprehensive input sanitization for $_SERVER variables
* Improved type safety throughout the codebase
* Added proper IP address validation and sanitization
* Fixed all deprecated code

**Documentation:**
* Added comprehensive deployment guide
* Added complete testing guide
* Added static analysis report
* Added detailed modifications log
* Added project summary documentation

**Technical Details:**
* All SQL queries now use wpdb->prepare() with proper placeholders
* Minimum PHP version updated from 5.6 to 7.4
* Tested with WordPress 6.7 and PHP 8.4
* Static analysis compliant (phpstan, psalm)

**Contributors:** Ojārs Kapteinis

= 2.0.0 (2020-05-14) =
* Code refactor following WordPress coding standards
* Added French translation
* Fixed plugin installation process
* Fixed Windows activation issues

= 1.8.1 (2019-09-30) =
* Added missing languages folder

= 1.8 (2019-09-30) =
* Fixed internationalization issues
* Added .pot file for translations
* Changed credit link default to not showing

= 1.7.1 (2016-09-13) =
* Fixed bug causing all IPv6 addresses to get locked out
* Added WordPress MultiSite functionality
* Fixed subnet matching bug
* Moved locked out IP report to its own tab

= 1.6.1 (2014-03-08) =
* Fixed HTML glitch preventing options from being saved

= 1.6 (2014-03-07) =
* Cleaned up deprecated functions
* Fixed bug with invalid property on non-object
* Fixed wpdb->prepare() utilization
* Added descriptive help text to options
* Added option to remove credit message

= 1.5 (2009-09-17) =
* Fixed SQL injection security vulnerability
* Implemented wp_nonce security
* Added XSS attack prevention
* Fixed 'Lockout Invalid Usernames' option

= 1.4 (2009-08-29) =
* Removed error affecting WP 2.8+
* Fixed activation error with custom wp-content location
* Added option to mask login errors
* Added option to lock out invalid usernames

= 1.3 (2009-02-23) =
* Adjusted plugin byline positioning
* Added dynamic file location support

= 1.2 (2008-06-15) =
* WordPress 2.5+ compatibility

= 1.1 (2007-09-01) =
* MySQL 4.0 compatibility fix

= 1.0 (2007-08-29) =
* Initial release

== Upgrade Notice ==

= 2.1.0 =
**CRITICAL SECURITY UPDATE** - This version fixes critical SQL injection vulnerabilities. Immediate update strongly recommended for all users. Includes PHP 8.4 compatibility improvements. Test in staging environment before production deployment.

= 2.0.0 =
Major code refactor with WordPress coding standards compliance. Backup before updating.

= 1.5 =
Security update fixing SQL injection vulnerability. Update immediately.

== Security ==

If you discover a security vulnerability, please contact the plugin maintainer directly before creating a public issue.

== Privacy Policy ==

Login LockDown stores the following data:
* IP addresses of failed login attempts
* Timestamps of failed login attempts
* Usernames used in failed login attempts

This data is stored locally in your WordPress database and is used solely for security purposes. No data is transmitted to external services.

Data retention:
* Failed login attempt records are automatically cleaned up based on your lockout settings
* Locked IP addresses are automatically released after the lockout period expires
* Administrators can manually clear all data from the admin panel

== Support ==

For support questions, bug reports, or feature requests:

* WordPress.org Support Forum: https://wordpress.org/support/plugin/login-lockdown/
* GitHub Issues: https://github.com/okapteinis/wp-login-lockdown/issues

== Credits ==

**Current Maintainer:** Ojārs Kapteinis (v2.1.0)
**Previous Maintainer:** Timothée Moulin (v2.0.0)
**Original Author:** Michael VanDeMar (v1.0 - v1.8)

== License ==

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
