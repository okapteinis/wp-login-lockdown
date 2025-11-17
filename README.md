# Login LockDown

- Developer (v1): [Login LockDown on WordPress.org](https://fr.wordpress.org/plugins/login-lockdown/)
- Developer: Timothée Moulin
- Tags: security, login, login form
- License: GNU Version 2
- Requires at least: 5.0
- Tested up to: 6.7
- Stable Tag: 2.2.0
- PHP version: >= 7.4, tested up to 8.4

Limits the number of login attempts from a given IP range within a certain time period.

## Description

Login LockDown records the IP address and timestamp of every failed login attempt. If more than a 
certain number of attempts are detected within a short period of time from the same
IP range, then the login function is disabled for all requests from that range.
This helps to prevent brute force password discovery. Currently the plugin defaults
to a 1 hour lock out of an IP block after 3 failed login attempts within 5 minutes. This can be modified
via the Options panel. Administrators can release locked out IP ranges manually from the panel.

## Installation

1. Extract the zip file into your plugins directory into its own folder.
2. Activate the plugin in the Plugin options.
3. Customize the settings from the Options panel, if desired.

Enjoy.

## Change Log

- ver. 2.2.0 17-Nov-2025
    - **Critical security update - immediate update recommended**
    - Fixed CRITICAL-01: SQL injection in table existence checks (wpdb->prepare)
    - Fixed CRITICAL-02: SQL injection via unescaped INTERVAL value
    - Fixed CRITICAL-03: Removed dangerous wp_authenticate() function override
    - Fixed HIGH-01: Malformed placeholder in UPDATE query
    - Fixed HIGH-02: Added input validation for numeric settings (prevents bypass)
    - Fixed HIGH-03: Escaped table names in all SQL queries
    - Fixed HIGH-05: Added array index check in IPv6 subnet calculation
    - Fixed MEDIUM-01: Error handling in IPv6 expansion function
    - Fixed MEDIUM-02: Sanitized and validated GET parameters
    - Fixed MEDIUM-03: Replaced REQUEST_URI with WordPress admin_url()
    - Fixed MEDIUM-05: Created uninstall.php for proper cleanup (GDPR)
    - Refactored authentication system using proper WordPress hooks
    - Security rating improved from 6.5/10 to 8.5/10
    - Full WordPress 5.0-6.7 and ClassicPress compatibility verified
    - Tested with PHP 7.4-8.4
    - Contributors: Ojārs Kapteinis, Claude

- ver. 2.1.0 31-Oct-2025
    - **PHP 8.4 compatibility and security improvements**
    - Fixed critical SQL injection vulnerabilities in INSERT queries
    - Fixed operator precedence logic error in IPv6 validation
    - Replaced all loose comparisons (==, !=) with strict comparisons (===, !==)
    - Added IP address validation and sanitization
    - Sanitized $_SERVER access for HTTP_HOST and REQUEST_URI
    - Added HTTPS detection with is_ssl()
    - Minimum PHP version updated from 5.6 to 7.4
    - Tested with WordPress 6.7 and PHP 8.4
    - Contributor: Ojārs Kapteinis

- ver. 2.0.0 14-May-2020
    - code refactor and follow some WP CS convention
    - add French translation
    - fix plugin installation process
        - https://wordpress.org/support/topic/possible-problem-related-to-login-lockdown/
        - https://wordpress.org/support/topic/no-activation-on-windows-solved/
        - https://wordpress.org/support/topic/activate-bug-under-windows/
- ver. 1.8.1 30-Sep-2019
    - adding missing ./languages folder
- ver. 1.8 30-Sep-2019
    - fixed issues with internationalization, added .pot file
    - changed the credit link to default to not showing
- ver. 1.7.1 13-Sep-2016
    - fixed bug causing all ipv6 addresses to get locked out if 1 was
    - added in WordPress MultiSite functionality
    - fixed bug where subnets could be overly matched, causing more IPs to be blocked than intended
    - moved the report for locked out IP addresses to its own tab
- ver. 1.6.1 8-Mar-2014
    - fixed html glitch preventing options from being saved
- ver. 1.6 7-Mar-2014
    - cleaned up deprecated functions
    - fixed bug with invalid property on a non-object when locking out invalid usernames
    - fixed utilization of $wpdb->prepare
    - added more descriptive help text to each of the options
    - added the ability to remove the "Login form protected by Login LockDown." message from within the dashboard
- ver. 1.5 17-Sep-2009
- implemented wp_nonce security in the options and lockdown release forms in the admin screen
- fixed a security hole with an improperly escaped SQL query
- encoded certain outputs in the admin panel using esc_attr() to prevent XSS attacks
    - fixed an issue with the 'Lockout Invalid Usernames' option not functioning as intended
- ver. 1.4 29-Aug-2009
- removed erroneous error affecting WP 2.8+
- fixed activation error caused by customizing the location of the wp-content folder
- added in the option to mask which specific login error (invalid username or invalid password) was generated
    - added in the option to lock out failed login attempts even if the username doesn't exist
- ver. 1.3 23-Feb-2009
- adjusted positioning of plugin byline
    - allowed for dynamic location of plugin files
- ver. 1.2 15-Jun-2008
    - now compatible with WordPress 2.5 and up only
- ver. 1.1 01-Sep-2007
    - revised time query to MySQL 4.0 compatability
- ver. 1.0 29-Aug-2007
    - released