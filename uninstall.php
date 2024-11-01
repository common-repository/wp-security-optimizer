<?php

// Check that code was called from WordPress with
// uninstallation constant declared
if ( !defined( 'WP_UNINSTALL_PLUGIN' ) )
exit;

global $wpdb;

define('SEC_OPT_ATTACKER',   $wpdb->get_blog_prefix() . 'sec_opt_attacker');
define('SEC_OPT_GENERAL_COUNTER',  $wpdb->get_blog_prefix() . 'sec_opt_counter');
define('SEC_OPT_ATTACK_HISTORY',  $wpdb->get_blog_prefix() . 'sec_opt_attack_history');

define( 'WP_SEC_OPT_OPTION_VER', 'sec_opt_version');
define( 'WP_SEC_OPT_OPTION_XMLRPC', 'sec_opt_xmlrpc');

define( 'WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS','sec_opt_bruteforce_login_attempts');
define( 'WP_SEC_OPT_OPTION_BF_SAMPLING', 'sec_opt_bruteforce_sampling');
define( 'WP_SEC_OPT_OPTION_BF_BAN_TIME', 'sec_opt_bruteforce_ban_time');
define( 'WP_SEC_OPT_OPTION_BF_SEND_EMAIL','sec_opt_bruteforce_send_email');
define( 'WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL','sec_opt_wpscan_send_email');

define( 'WP_SEC_OPT_OPTION_CHECKBOX_PROXY','sec_opt_proxy');
define( 'WP_SEC_OPT_OPTION_PROXY_IP','sec_opt_proxy_ip');

// Check if options exist and delete them if present

if ( get_option(WP_SEC_OPT_OPTION_VER) != false ) delete_option(WP_SEC_OPT_OPTION_VER);
if ( get_option(WP_SEC_OPT_OPTION_XMLRPC) != false ) delete_option(WP_SEC_OPT_OPTION_XMLRPC);

if ( get_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS) != false ) delete_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS);
if ( get_option(WP_SEC_OPT_OPTION_BF_SAMPLING) != false ) delete_option(WP_SEC_OPT_OPTION_BF_SAMPLING);
if ( get_option(WP_SEC_OPT_OPTION_BF_BAN_TIME) != false ) delete_option(WP_SEC_OPT_OPTION_BF_BAN_TIME);
if ( get_option(WP_SEC_OPT_OPTION_BF_SEND_EMAIL) != false ) delete_option(WP_SEC_OPT_OPTION_BF_SEND_EMAIL);
if ( get_option(WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL) != false ) delete_option(WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL);


if ( get_option(WP_SEC_OPT_OPTION_PROXY_IP) != false ) delete_option(WP_SEC_OPT_OPTION_PROXY_IP);
if ( get_option(WP_SEC_OPT_OPTION_CHECKBOX_PROXY) != false ) delete_option(WP_SEC_OPT_OPTION_CHECKBOX_PROXY);


$wpdb->query ($wpdb->prepare( 'DROP TABLE ' . SEC_OPT_ATTACKER) );
$wpdb->query ($wpdb->prepare( 'DROP TABLE ' . SEC_OPT_GENERAL_COUNTER) );
$wpdb->query ($wpdb->prepare( 'DROP TABLE ' . SEC_OPT_ATTACK_HISTORY) );

?>
