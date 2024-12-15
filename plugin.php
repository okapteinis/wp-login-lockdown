<?php
/**
 * Plugin Name: Login LockDown
 * Description: Adds extra security to WordPress by restricting the rate of failed login attempts from a given IP range.
 * Version: 1.1.2
 * Requires PHP: 8.4
 */

if (!defined('WPINC')) {
    die;
}

$loginlockdown_db_version = "1.1.2";

if (!defined('WP_PLUGIN_DIR')) {
    define('WP_PLUGIN_DIR', ABSPATH . 'wp-content/plugins');
}

/**
 * Triggered during plugin install.
 * Create the database structure.
 */
function loginlockdown_install(): void {
    global $wpdb;
    $table_name = $wpdb->prefix . "login_fails";

    if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") !== $table_name) {
        $sql = "CREATE TABLE {$table_name} (
            `login_attempt_ID` BIGINT(20) NOT NULL AUTO_INCREMENT,
            `user_id` BIGINT(20) NOT NULL,
            `login_attempt_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `login_attempt_IP` VARCHAR(100) NOT NULL DEFAULT '',
            PRIMARY KEY (`login_attempt_ID`)
        );";
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    $table_name = $wpdb->prefix . "lockdowns";

    if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") !== $table_name) {
        $sql = "CREATE TABLE {$table_name} (
            `lockdown_ID` BIGINT(20) NOT NULL AUTO_INCREMENT,
            `user_id` BIGINT(20) NOT NULL,
            `lockdown_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `release_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `lockdown_IP` VARCHAR(100) NOT NULL DEFAULT '',
            PRIMARY KEY (`lockdown_ID`)
        );";
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    add_option("loginlockdown_db_version", "1.0", "", "no");
    delete_option("loginlockdown_db1_version");
    delete_option("loginlockdown_db2_version");
}
register_activation_hook(__FILE__, 'loginlockdown_install');

/**
 * Return the number of failing attempts for one username.
 */
function loginlockdown_count_fails(string $username = ""): ?string {
    global $wpdb;
    $loginlockdownOptions = loginlockdown_get_options();
    $table_name = $wpdb->prefix . "login_fails";
    $subnet = loginlockdown_calculate_subnet($_SERVER['REMOTE_ADDR']);
    
    $numFailsquery = "
        SELECT COUNT(login_attempt_ID)
        FROM {$table_name}
        WHERE login_attempt_date + INTERVAL %d MINUTE > NOW()
          AND login_attempt_IP LIKE %s
    ";
    
    return $wpdb->get_var($wpdb->prepare($numFailsquery, $loginlockdownOptions['retries_within'], "{$subnet[1]}%"));
}

/**
 * Increment the failing attempts number for a username.
 */
function loginlockdown_increment_fails(string $username = ""): void {
    global $wpdb;
    $loginlockdownOptions = loginlockdown_get_options();
    $table_name = $wpdb->prefix . "login_fails";
    $subnet = loginlockdown_calculate_subnet($_SERVER['REMOTE_ADDR']);
    
    $username = sanitize_user($username);
    $user = get_user_by('login', $username);
    
    if ($user || $loginlockdownOptions['lockout_invalid_usernames'] === "yes") {
        $user_id = ($user === false) ? -1 : (int)$user->ID;

        $insert = "
            INSERT INTO {$table_name} (user_id, login_attempt_date, login_attempt_IP)
            VALUES (%d, NOW(), %s)
        ";
        
        $wpdb->query($wpdb->prepare($insert, $user_id, "{$subnet[0]}"));
    }
}

/**
 * Lock a username.
 */
function loginlockdown_lock_username(string $username = ""): void {
    global $wpdb;
    $loginlockdownOptions = loginlockdown_get_options();
    $table_name = $wpdb->prefix . "lockdowns";
    $subnet = loginlockdown_calculate_subnet($_SERVER['REMOTE_ADDR']);
    
    $username = sanitize_user($username);
    $user = get_user_by('login', $username);
    
    if ($user || $loginlockdownOptions['lockout_invalid_usernames'] === "yes") {
        $user_id = ($user === false) ? -1 : (int)$user->ID;

        $insert = "
            INSERT INTO {$table_name} (user_id, lockdown_date, release_date, lockdown_IP)
            VALUES (%d, NOW(), DATE_ADD(NOW(), INTERVAL %d MINUTE), %s)
        ";
        
        $wpdb->query($wpdb->prepare($insert, (int)$user_id, (int)$loginlockdownOptions['lockout_length'], "{$subnet[0]}"));
    }
}

/**
 * Check if IP has been locked.
 */
function loginlockdown_is_ip_locked(): ?string {
    global $wpdb;
    $table_name = $wpdb->prefix . "lockdowns";
    $subnet = loginlockdown_calculate_subnet($_SERVER['REMOTE_ADDR']);
    
    $stillLockedquery = "
        SELECT user_id
        FROM {$table_name}
        WHERE release_date > NOW()
          AND lockdown_IP LIKE %s
    ";
    
    return (string)$wpdb->get_var($wpdb->prepare($stillLockedquery, "{$subnet[1]}%"));
}

/**
 * Get the locked IP addresses.
 */
function loginlockdown_list_locked_ips(): array {
    global $wpdb;
    $table_name = $wpdb->prefix . "lockdowns";
    
    return (array)$wpdb->get_results("
        SELECT lockdown_ID, FLOOR((UNIX_TIMESTAMP(release_date)-UNIX_TIMESTAMP(NOW()))/60) AS minutes_left,
               lockdown_IP
        FROM {$table_name}
        WHERE release_date > NOW()
     ", ARRAY_A);
}

/**
 * Get the plugin options.
 */
function loginlockdown_get_options(): array {
    // Default options
    static array $_defaultOptions = [
        'max_login_retries' => 3,
        'retries_within' => 5,
        'lockout_length' => 60,
        'lockout_invalid_usernames' => 'no',
        'mask_login_errors' => 'no',
        'show_credit_link' => 'no',
    ];

   // Fetch options from database
   return array_merge($_defaultOptions, get_option("loginlockdown_admin_options", []));
}

/**
 * Get the IP address subnet.
 */
function loginlockdown_calculate_subnet(string $_ip): array {
   // Initialize subnet with full IP address
   $_subnet[0] = $_ip;

   // Check if it's an IPv6 address
   if (!filter_var($_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
       $_ip = loginlockdown_expand_ipv6($_ip);
       preg_match("/^([0-9a-f]{1,4}:){4}/", $_ip, $_matches);
       $_subnet[0] = $_ip;
       $_subnet[1] = $_matches[0];
   } else {
       $_subnet[1] = substr($_ip, 0, strrpos($_ip, ".") + 1);
   }

   return $_subnet;
}

/**
 * Get the expanded IPv6 format.
 */
function loginlockdown_expand_ipv6(string $_ip): string|false {
   // Convert to hexadecimal and expand IPv6 address
   $_hex = unpack("H*hex", inet_pton($_ip));
   return substr(preg_replace("/([A-f0-9]{4})/", "$1:", $_hex['hex']), 0, -1);
}

/**
 * Print the admin option page.
 */
function loginlockdown_admin_page(): void {
   global $_POST;

   // Fetch plugin options
   $_options = loginlockdown_get_options();

   // Check if form is submitted and nonce is valid
   if (isset($_POST['update_login_lock_down_settings']) && check_admin_referer('update-login-lock-down-options')) {

       // Update options based on form input
       foreach ($_options as $__key => $__value) {
           if (isset($_POST[$__key])) {
               $_options[$__key] = sanitize_text_field($_POST[$__key]);
           }
       }

       // Save updated options to database
       update_option("login_lock_down_admin_options", $_options);

       echo '<div id="message" class="updated fade"><p><strong>' . __('Settings saved.', 'textdomain') . '</strong></p></div>';
   }

   // Display admin page form with current settings
   ?>
   <div class="wrap">
       <h2><?php _e('Login LockDown Settings', 'textdomain'); ?></h2>
       <form method="post" action="">
           <?php wp_nonce_field('update-login-lock-down-options'); ?>
           <table class="form-table">
               <!-- Add form fields here -->
           </table>
           <p class="submit">
               <input type="submit" name="Submit" class="button-primary" value="<?php esc_attr_e('Save Changes', 'textdomain'); ?>" />
           </p>
       </form>
   </div>
   <?php
}
