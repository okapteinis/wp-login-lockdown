# Login LockDown

- Developer (v1)
- Developer: Timothée Moulin
- Contributor (v1.1.2): Ojārs Kapteinis
- Website: [ojars.kapteinis.lv](https://ojars.kapteinis.lv)
- Tags: security, login, login form
- License: GNU Version 2
- Requires at least: 3.6
- Tested up to: 5.4.1
- Stable Tag: 1.1.2
- PHP version: >=8.4

Limits the number of login attempts from a given IP range within a certain time period.

## Description

Login LockDown records the IP address and timestamp of every failed login attempt. If more than a certain number of attempts are detected within a short period of time from the same IP range, then the login function is disabled for all requests from that range.

This helps to prevent brute force password discovery. Currently, the plugin defaults to a 1-hour lockout of an IP block after 3 failed login attempts within 5 minutes. This can be modified via the Options panel. Administrators can release locked out IP ranges manually from the panel.

## Installation

1. Extract the zip file into your plugins directory into its own folder.
2. Activate the plugin in the Plugin options.
3. Customize the settings from the Options panel, if desired.

Enjoy.

## Change Log

- ver. 1.1.2 15-Dec-2024
  - Updated for PHP 8.4 compatibility by Ojārs Kapteinis ([ojars.kapteinis.lv](https://ojars.kapteinis.lv))
  - Modernized codebase with explicit type declarations and updated database defaults
  - Improved security with stricter validation and sanitization

- ver. 2.0.0 14-May-2020
  - Code refactor and follow some WP CS convention
  - Added French translation
  - Fixed plugin installation process
  - [Possible problem related to Login LockDown](https://wordpress.org/support/topic/possible-problem-related-to-login-lockdown/)
  - [No activation on Windows (solved)](https://wordpress.org/support/topic/no-activation-on-windows-solved/)
  - [Activate bug under Windows](https://wordpress.org/support/topic/activate-bug-under-windows/)

- ver. 1.8.1 30-Sep-2019
  - Added missing `./languages` folder

- ver. 1.8 30-Sep-2019
  - Fixed issues with internationalization, added `.pot` file
  - Changed the credit link to default to not showing

- ver. 1.7.1 13-Sep-2016
  - Fixed bug causing all IPv6 addresses to get locked out if one was
  - Added WordPress MultiSite functionality
  - Fixed bug where subnets could be overly matched, causing more IPs to be blocked than intended
  - Moved the report for locked out IP addresses to its own tab

- ver. 1.6.1 8-Mar-2014
  - Fixed HTML glitch preventing options from being saved

- ver. 1.6 7-Mar-2014
  - Cleaned up deprecated functions
  - Fixed bug with invalid property on a non-object when locking out invalid usernames
  - Fixed utilization of `$wpdb->prepare`
  - Added more descriptive help text to each of the options
  - Added the ability to remove the "Login form protected by Login LockDown." message from within the dashboard

- ver. 1.5 17-Sep-2009
  - Implemented `wp_nonce` security in the options and lockdown release forms in the admin screen
  - Fixed a security hole with an improperly escaped SQL query
  - Encoded certain outputs in the admin panel using `esc_attr()` to prevent XSS attacks
  - Fixed an issue with the 'Lockout Invalid Usernames' option not functioning as intended

- ver. 1.4 29-Aug-2009
  - Removed erroneous error affecting WP 2.8+
  - Fixed activation error caused by customizing the location of the wp-content folder
  - Added in the option to mask which specific login error (invalid username or invalid password) was generated
  - Added in the option to lock out failed login attempts even if the username doesn't exist

- ver. 1.3 23-Feb-2009
   - Adjusted positioning of plugin byline
   - Allowed for dynamic location of plugin files

- ver. 1.2 15-Jun-2008
   - Now compatible with WordPress version >=2.5 only

- ver. 1.1 Sept-2007 
   Revised time-query MYSQL compatability.
