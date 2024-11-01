<?php
/*
   Plugin Name: WP Security Optimizer
   Plugin URI: https://www.wp-security-optimizer.com/
   Description: Protect your site from vulnerability scanner and hackers
   Version: 1.5.15
   Author: Luca Ercoli
   Author URI: http://www.lucaercoli.it/
   License: GPL2
   License URI: https://www.gnu.org/licenses/gpl-2.0.html
   Text Domain: lucaercoliit
 */



/* Block direct access */
if (!defined('ABSPATH')) {
	die('Direct access not allowed!');
}


//Entries in the site's options table
define( 'WP_SEC_OPT_PLUGIN_VER', '1.5.15' );
define( 'WP_SEC_OPT_OPTION_VER', 'sec_opt_version');
define( 'WP_SEC_OPT_OPTION_XMLRPC', 'sec_opt_xmlrpc');

define( 'WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS','sec_opt_bruteforce_login_attempts');
define( 'WP_SEC_OPT_OPTION_BF_SAMPLING', 'sec_opt_bruteforce_sampling');
define( 'WP_SEC_OPT_OPTION_BF_BAN_TIME', 'sec_opt_bruteforce_ban_time');
define( 'WP_SEC_OPT_OPTION_BF_SEND_EMAIL','sec_opt_bruteforce_send_email');
define( 'WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL','sec_opt_wpscan_send_email');

define( 'WP_SEC_OPT_OPTION_CHECKBOX_PROXY','sec_opt_proxy');
define( 'WP_SEC_OPT_OPTION_PROXY_IP','sec_opt_proxy_ip');

//Database tables
define('SEC_OPT_ATTACKER', 'sec_opt_attacker');
define('SEC_OPT_GENERAL_COUNTER', 'sec_opt_counter');
define('SEC_OPT_ATTACK_HISTORY', 'sec_opt_attack_history');

//Attack types
define('SEC_OPT_ATTACK_TYPE_XMLRPC', 'total_xmlrpc_attack');
define('SEC_OPT_ATTACK_TYPE_BRUTEFORCE', 'total_bruteforce_attack');
define('SEC_OPT_ATTACK_TYPE_WPSCAN', 'total_wpscan_attack');
define('SEC_OPT_ATTACK_TYPE_USERAGENT', 'total_badbot_attack');


//DB Values
define ('SEC_OPT_XMLRPC_ATTACK_ID', 'XMLRPC');
define ('SEC_OPT_WPLOGIN_ATTACK_ID', 'WPLOGIN');
define ('SEC_OPT_WPSCAN_ATTACK_ID', 'WPSCAN');
define ('SEC_OPT_USERAGENT_ATTACK_ID', 'BADUSERAGENT');
define ('SEC_OPT_WHATWEB_ATTACK_ID', 'WHATWEB');


/*
   Analyzing the User-Agent field in the HTTP request headers,
   disallow access on your Website to the most widespread
   penetration test and security assessment applications, including:
   WPScan, OpenVAS, Nikto, sqlmap, commix and skipfish
 */
function sec_opt_check_useragent()
{

	$bad_UA = array (
			'WPScan',
			' OpenVAS ',
			'Nikto/',
			'sqlmap/',
			'commix/',
			'WhatWeb/',
			'Mozilla/5.0 SF/'
			);

	$http_return_code="406";
	$error_message="Not Acceptable";

	foreach ($bad_UA as $value) {

		if (strstr($_SERVER['HTTP_USER_AGENT'],$value)!= FALSE)
		{
			status_header($http_return_code);



			if (sec_opt_can_writeDB(SEC_OPT_USERAGENT_ATTACK_ID,0)) {

				if (strstr($_SERVER['HTTP_USER_AGENT'],'WPScan')!= FALSE)
				{ 
					sec_opt_incr_attack_counter_DB(SEC_OPT_ATTACK_TYPE_WPSCAN);
					sec_opt_save_attack_history($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], SEC_OPT_WPSCAN_ATTACK_ID);
					sec_opt_send_alert('assets/pages/email_alert_wpscan.php');
				}
				else if(strstr($_SERVER['HTTP_USER_AGENT'],'WhatWeb/')!= FALSE)
				{	
					sec_opt_incr_attack_counter_DB(SEC_OPT_ATTACK_TYPE_WPSCAN);
					sec_opt_save_attack_history($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], SEC_OPT_WHATWEB_ATTACK_ID);
					//sec_opt_send_alert('assets/pages/email_alert_whatweb.php');
				}
				else {
					sec_opt_save_attack_history($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], SEC_OPT_USERAGENT_ATTACK_ID);
					sec_opt_incr_attack_counter_DB(SEC_OPT_ATTACK_TYPE_USERAGENT);
				}
			}

			die($error_message);
		}

	}

}


//Massive attacks can exhaust database's resources. 
//In order to avoid this problem, counters for the same attacker's IP will be handled with a session timeout (10 secs)
function sec_opt_can_writeDB($reason, $wp_login_bruteforce){

	$seconds = 10;

	$global_check=0;

	        $sec_proxy_option = get_option( WP_SEC_OPT_OPTION_CHECKBOX_PROXY );

                if ($sec_proxy_option == 'OFF' )
                {

	$remote_address = $_SERVER['REMOTE_ADDR'];
$global_check=1;
}
	else{
                $IPAddressForwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $sec_proxy_addr = get_option( WP_SEC_OPT_OPTION_PROXY_IP );
		
if ( ( ($_SERVER['REMOTE_ADDR'] == $sec_proxy_addr)  && isset($IPAddressForwardedFor) ) && (  (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false)  || (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false ) ) ) { $remote_address = $IPAddressForwardedFor; $global_check=1; }

}

if ( $global_check ){
	sec_opt_remove_oldest_entries_from_db(SEC_OPT_ATTACKER,$seconds);

	if (!sec_opt_DB_value_lessthan($remote_address, SEC_OPT_ATTACKER, $seconds, $wp_login_bruteforce)) {

		global $wpdb;
		$table_name = $wpdb->prefix . SEC_OPT_ATTACKER;

		$wpdb->query( $wpdb->prepare( "INSERT INTO " . $table_name . "(IP_attacker,type_attack) values('%s','%s')", $remote_address, $reason  ) );

		return true;
	}

}

	return false;
}



function sec_opt_send_alert($require_file){

	require($require_file);

	$admin_email = get_bloginfo('admin_email');

	$headers = "From: WP Security Optimizer :<" . $admin_email . ">\r\n";
	$headers .= "Content-Type: text/html; charset=UTF-8\r\n";

	if ( strstr($require_file,"wplogin") != FALSE ){

		$wplogin_option = get_option( WP_SEC_OPT_OPTION_BF_SEND_EMAIL );

		if ($wplogin_option == 'ON' )	
		{ 
			wp_mail( $admin_email, $subject, $html_body, $headers ); 
		}
	}

	else 
	{
		


$wpscan_option = get_option( WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL );

                if ($wpscan_option == 'ON' )
                {
		wp_mail( $admin_email, $subject, $html_body, $headers );
	}
}
}

//Check and (eventually) synchronize database structure
function sec_opt_check_and_sync_database()
{

	require('assets/lib/database_table.php');
	require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

	dbDelta( $sql_query_attacker );
	dbDelta( $sql_query_general_counter );
	dbDelta( $sql_query_attack_history );

	global $wpdb;
	$my_value = 1;

	$table_name = $wpdb->prefix . SEC_OPT_GENERAL_COUNTER;

	$result = $wpdb->get_results("SELECT id from `$table_name` WHERE `id` IS NOT NULL");
	if(count($result) == 0)
	{
		$wpdb->query( $wpdb->prepare( "INSERT into `$table_name`(id) value(%d)",$my_value));
	}


}




//Increment attack counters
//Available counters: SEC_OPT_ATTACK_TYPE_XMLRPC, SEC_OPT_ATTACK_TYPE_BRUTEFORCE, SEC_OPT_ATTACK_TYPE_VULNSCAN
function sec_opt_incr_attack_counter_DB($attack_type)
{
	global $wpdb;
	$my_value=1;
	
	$table_name = $wpdb->prefix . SEC_OPT_GENERAL_COUNTER;

	//$wpdb->query( $wpdb->prepare( "UPDATE `wssp_sec_opt_counter` SET `$attack_type` = `$attack_type` + 1 WHERE id = '%d'",$my_value ) );
	$wpdb->query( $wpdb->prepare( "UPDATE `$table_name` SET `$attack_type` = `$attack_type` + 1 WHERE id = '%d'",$my_value ) );

}


//Remove all entries into $table older than $time_period (seconds)
//Support the following datasets: SEC_OPT_ATTACK_HISTORY, SEC_OPT_ATTACKER
function sec_opt_remove_oldest_entries_from_db($table, $time_period)
{

	global $wpdb;
	$table_name = $wpdb->prefix . $table;


	$wpdb->query( $wpdb->prepare( "DELETE FROM `$table_name` WHERE `last_seen_timestamp` < (NOW() - INTERVAL %d SECOND) AND `type_attack`!='%s'", $time_period,SEC_OPT_WPLOGIN_ATTACK_ID) );

	$wpdb->query( $wpdb->prepare( "DELETE FROM `$table_name` WHERE `last_seen_timestamp` < (NOW() - INTERVAL %d SECOND) AND `type_attack`='%s'", get_option(WP_SEC_OPT_OPTION_BF_SAMPLING),SEC_OPT_WPLOGIN_ATTACK_ID) );

}




//Check if $attacker_IP is stored into $table and it's SEC_OPT_WPLOGIN_ATTACK_ID
//Support the following datasets: SEC_OPT_ATTACK_HISTORY, SEC_OPT_ATTACKER
//Ex: if ( sec_opt_isset_in_DB('9.9.9.12',SEC_OPT_ATTACK_HISTORY) ) {echo "I'm here"; exit; }
function sec_opt_isset_in_DB($attacker_IP, $table)
{
	global $wpdb;
	$table_name = $wpdb->prefix . $table;

	$ret_value = $wpdb->query( $wpdb->prepare( "select `IP_attacker` from `$table_name` where `IP_attacker`='%s' AND `type_attack`='%s'",$attacker_IP,SEC_OPT_WPLOGIN_ATTACK_ID) );

	if ($ret_value) return true;
	else return false;

}



function sec_opt_save_attack_history($attacker_IP, $useragent, $type_attack)
{

	global $wpdb;
	$table_name = $wpdb->prefix . SEC_OPT_ATTACK_HISTORY;

	$sec_proxy_option = get_option( WP_SEC_OPT_OPTION_CHECKBOX_PROXY );

	if ($sec_proxy_option == 'OFF' )
	{
		$wpdb->query( $wpdb->prepare( "INSERT INTO `$table_name`(IP_attacker,useragent,type_attack) values('%s','%s','%s')",$attacker_IP, $useragent, $type_attack) );
	}
	else
	{
		$IPAddressForwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'];
		$sec_proxy_addr = get_option( WP_SEC_OPT_OPTION_PROXY_IP );

		if ( ( ($_SERVER['REMOTE_ADDR'] == $sec_proxy_addr)  && isset($IPAddressForwardedFor) ) && (  (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false)  || (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false )) )
		{
			$wpdb->query( $wpdb->prepare( "INSERT INTO `$table_name`(IP_attacker,useragent,type_attack) values('%s','%s','%s')",$IPAddressForwardedFor, $useragent, $type_attack) );
		}

	}

}


function sec_opt_is_max_login_reached(){

	global $wpdb;
	$table_name = $wpdb->prefix . SEC_OPT_ATTACKER;

$sec_proxy_option = get_option( WP_SEC_OPT_OPTION_CHECKBOX_PROXY );

 if ($sec_proxy_option == 'OFF' )
                {

	$ret_value = $wpdb->query( $wpdb->prepare( "SELECT `IP_attacker` FROM `$table_name` WHERE `IP_attacker`='%s' AND `type_attack`='%s' AND `fail_log_counter` >= %d AND `last_seen_timestamp` > (NOW() - INTERVAL %d SECOND)", $_SERVER['REMOTE_ADDR'], SEC_OPT_WPLOGIN_ATTACK_ID, get_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS), get_option(WP_SEC_OPT_OPTION_BF_BAN_TIME)  ) );

	if ($ret_value) return true;
	else return false;
}

else {

$IPAddressForwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $sec_proxy_addr = get_option( WP_SEC_OPT_OPTION_PROXY_IP );
                if ( ( ($_SERVER['REMOTE_ADDR'] == $sec_proxy_addr)  && isset($IPAddressForwardedFor) ) && (  (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false)  || (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false )) ){

$ret_value = $wpdb->query( $wpdb->prepare( "SELECT `IP_attacker` FROM `$table_name` WHERE `IP_attacker`='%s' AND `type_attack`='%s' AND `fail_log_counter` >= %d AND `last_seen_timestamp` > (NOW() - INTERVAL %d SECOND)", $IPAddressForwardedFor, SEC_OPT_WPLOGIN_ATTACK_ID, get_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS), get_option(WP_SEC_OPT_OPTION_BF_BAN_TIME)  ) );

        if ($ret_value) return true;
        else return false;
}

}


}


//Check if $attacker_IP into $table is more recent than $time_period (seconds)
//Support the following datasets: SEC_OPT_ATTACK_HISTORY, SEC_OPT_ATTACKER
//Ex: if (sec_opt_DB_value_lessthan('9.9.9.10', SEC_OPT_ATTACK_HISTORY, 60)) {echo "Too recent!"; exit; }
function sec_opt_DB_value_lessthan($attacker_IP, $table, $time_period, $wp_login_bruteforce)
{

	global $wpdb;
	$table_name = $wpdb->prefix . $table;
	$ret_value = false;

	if($wp_login_bruteforce == 0)
	{
		$ret_value = $wpdb->query( $wpdb->prepare( "SELECT `IP_attacker` FROM `$table_name` WHERE `IP_attacker`='%s' AND `last_seen_timestamp` > (NOW() - INTERVAL %d SECOND) AND `type_attack`!='%s'", $attacker_IP, $time_period,SEC_OPT_WPLOGIN_ATTACK_ID) );
	}
	else 
	{


		if (!sec_opt_isset_in_DB($attacker_IP, $table)){
			$wpdb->query( $wpdb->prepare( "INSERT INTO `$table_name`(IP_attacker,type_attack) values('%s','%s')",$attacker_IP, SEC_OPT_WPLOGIN_ATTACK_ID) );
		}
		else
		{
			//Increase failed login counter
			$wpdb->query( $wpdb->prepare( "UPDATE `$table_name` SET `fail_log_counter`=`fail_log_counter` + 1  WHERE `type_attack` = '%s' AND `IP_attacker`='%s'",SEC_OPT_WPLOGIN_ATTACK_ID,$attacker_IP ) );

			$howmany = $wpdb->get_var(  $wpdb->prepare( "SELECT `fail_log_counter` FROM `$table_name` WHERE `IP_attacker` = '%s' AND `type_attack` = '%s'", $attacker_IP, SEC_OPT_WPLOGIN_ATTACK_ID ) );

			if ($howmany >= get_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS) )
			{
				sec_opt_save_attack_history($attacker_IP, $_SERVER['HTTP_USER_AGENT'], SEC_OPT_WPLOGIN_ATTACK_ID);
				sec_opt_incr_attack_counter_DB(SEC_OPT_ATTACK_TYPE_BRUTEFORCE);

				sec_opt_send_alert('assets/pages/email_alert_wplogin.php');

			}

		}


		$ret_value = $wpdb->query( $wpdb->prepare( "SELECT `IP_attacker` FROM `$table_name` WHERE `IP_attacker`='%s' AND `last_seen_timestamp` > (NOW() - INTERVAL %d SECOND) AND `type_attack`='%s'", $attacker_IP, get_option(WP_SEC_OPT_OPTION_BF_BAN_TIME),SEC_OPT_WPLOGIN_ATTACK_ID) );

	}

	if ($ret_value) return true;
	else return false;


}



/*
   This routine implements functionalities to evade vulnerability scanners
 */

function sec_opt_evasion($require_file)
{

	require($require_file);

	$page_content = '<html><head><title>Index of</title></head><body></body></html>';

	$dummy_file_content = '<?php define(\'DB_HOST\', \'localhost\'); define(\'DB_CHARSET\', \'utf8mb4\'); define(\'DB_COLLATE\', \'\');';

	$fake_version = 'Stable tag: 2';



	//Determining if HTTP URI matches in data set rules
	foreach ($data as $value) {

		//It matchs. We've a candidate to be analyzed	
		if ( strstr($_SERVER['REQUEST_URI'],$value) != FALSE ){

			//Determine whether the end $_SERVER[REQUEST_URI] instance matches the specified $value
			$length = strlen($value);
			if ( substr($_SERVER['REQUEST_URI'], -$length) === $value )
			{

				status_header(200);

				//Responds with fake informations in order to elude vulnerability scanners 
				if (strstr($require_file,"passive_detection") != FALSE) {
					echo $fake_version; 
				}
				else if (strstr($require_file,"sensitive_file.php") != FALSE) { 

					//Recognizing a common probing pattern
					//WPScan
					if ( strstr($value,'wp-config.php.save') != FALSE ){
						if (sec_opt_can_writeDB(SEC_OPT_WPSCAN_ATTACK_ID,0)) {	
							sec_opt_save_attack_history($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], SEC_OPT_WPSCAN_ATTACK_ID);
							sec_opt_incr_attack_counter_DB(SEC_OPT_ATTACK_TYPE_WPSCAN);
							sec_opt_send_alert('assets/pages/email_alert_wpscan.php');
						}

					}

					echo $dummy_file_content;
				}

				die();
			}
		}
	}
}


//Called by admin_notice's action in order to display a notice regards files that expose version number and reveal potential vulnerabilities
function sec_opt_display_admin_sec_notices() {

	sec_opt_print_file_warning("1");

}


//Display "notice" listing files that expose version number and reveal potential vulnerabilities
//called by sec_opt_print_file_warning()
function sec_opt_print_notice_text()
{


	$msg="<strong>WP Security Optimizer</strong> has detected files that expose version number. <a href=\"#\" onClick=\"ReportWindow=window.open('" . "admin-ajax.php?action=admin_security_notice" ."','ReportWindow',width=600,height=300); return false;\">Click Here</a> for more information";

	echo '<div class="error notice is-dismissible"><p>';
	_e( $msg, 'lucaercoliit' );
	echo '</p></div>';

}


//Print just a notice or the complete report's link 
function sec_opt_print_file_warning ($brief)
{

	require('assets/lib/sensitive_file_admin.php');
	require('assets/pages/header.php');
	require('assets/pages/footer.php');

	$check_for = array (
			'/readme.txt',
			'/readme.htm',
			'/readme.html',
			'/changelog.txt'
			);

	$button_close = '<input type="button" value="Close this window" onclick="self.close()">';

	$err_msg = '<br /> <br />Something went wrong. Probably you don\'t have permission to perform this action (delete).<br />Set the correct ownership on the web server\'s directory and try again, or remove it by hand ';
	$success_msg = '<br /> <br />Success! All files has been removed ';


	$objects = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(WP_CONTENT_DIR));
	$objects->setMaxDepth(2);

	$n_files_left = 0;
	$n_files = 0;

	//If we must generate report, print the header of the web page that list files 
	//actually used by developers (such of backup of Wordpress's configuration), page
	//accessible but unlinked and README files that expose version number and reveal 
	//potential vulnerabilities
	if (!$brief) {
		echo $html_source_header;
	}

	foreach($objects as $name => $object){

		foreach ($check_for as $value) {

			if (stristr($name,$value) != FALSE)
			{
				$length = strlen($value);
				if ( substr($name, -$length) === $value ){

					$n_files++;

					if ($brief){
						//Print just the notice in the Administration Screen
						sec_opt_print_notice_text();
						return;
					}
					else {
						//User wants to remove files
						if (isset($_GET['delete'])) { 
							@unlink($name);
							$return_stat=@stat($name);
							//Can't remove file. Print it's name and increase our counter ($n_files_left) of missed unlink()
							if($return_stat) {
								$n_files_left++;
								echo '<li>' . $name . '</li>';
							}
						}	
						else{
							//Display the report body
							echo '<li>' . $name . '</li>';
						}
					}
				}
			}
		}
	}


	//Checking backup of Wordpress's configuration
	foreach ($data as $value) {

		$stat_file = @stat(ABSPATH . $value);

		if ($stat_file) 
		{
			$n_files++;

			if ($brief){
				//Print just the notice in the Administration Screen
				sec_opt_print_notice_text();
				return;
			}
			else {
				//User wants to remove files
				if (isset($_GET['delete'])) {
					@unlink(ABSPATH . $value);
					$return_stat=@stat(ABSPATH . $value);
					//Can't remove file. Print it's name and increase our counter ($n_files_left) of missed unlink()
					if($return_stat) {
						$n_files_left++;
						echo '<li>' . ABSPATH . $value . '</li>';
					}
				}
				else{
					//Display the report body
					echo '<li>' .  ABSPATH . $value . '</li>';
				}
			}
		}
	}


	if ($n_files){
		//Print "delete" link
		if (!isset($_GET['delete'])) {
			echo '<br /> <br /><a href="admin-ajax.php?action=admin_security_notice&delete=1">Click here to fix and delete files</a>';
			echo $html_source_footer;
		}

		//Print the result
		else {
			if ($n_files_left > 0) {
				echo $err_msg;
				echo $button_close;
				echo $html_source_footer;
			}
			else {
				echo $success_msg;
				echo $button_close;
				echo $html_source_footer;
			}
		}	
	}


}



//Checking files that expose version number and reveal potential vulnerabilities
function sec_opt_admin_security_notice() {

	if ( is_super_admin() ){
		sec_opt_print_file_warning("0");
		die();
	}

}


/*
   The inspection engine monitors the traffic between clients and your Website, enhancing the security
   of your WordPress installation replying with fake informations to vulnerability scanners.
   Specially designed for WPScan where it's able to induce false-positives, hide some well-known plugins
   and generate an unreadable report full of thousand wrong data
 */
function sec_opt_request_inspection()
{

	//Replace "X-Meta-Generator" header with fake informations
	if ( !is_super_admin() ){
		$GLOBALS['wp_version'] = rand(61282,99999);
	}

	if ( strstr($_SERVER['REQUEST_URI'],"xmlrpc.php") != FALSE ){

		//Determine whether the end $_SERVER[REQUEST_URI] instance matches the specified $value
		//$length = strlen($value); value è "xmlrpc.php"
		$length = 10;
		if ( substr($_SERVER['REQUEST_URI'], -$length) === "xmlrpc.php" )
		{

			$xml_rpc_option = get_option( 'sec_opt_xmlrpc' );
			if ($xml_rpc_option == 'ON' ) {
				if (sec_opt_can_writeDB(SEC_OPT_XMLRPC_ATTACK_ID,0)) {
					sec_opt_save_attack_history($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], SEC_OPT_XMLRPC_ATTACK_ID);
					sec_opt_incr_attack_counter_DB(SEC_OPT_ATTACK_TYPE_XMLRPC);
				}
			}
		}

	}


	if ( !is_super_admin() ){
	if ( sec_opt_is_max_login_reached() ){

		$http_return_code="406";

		$image_logo = WP_PLUGIN_URL . "/wp-security-optimizer/assets/images/attack-blocked.png";

		$block_page= "<span style=\"font-size: 23px;\">Attack blocked by </span><br /><br /><a target=\"_blank\" href=\"https://www.wp-security-optimizer.com\"><img src=\"". $image_logo . "\" />";

		status_header($http_return_code);

		die($block_page);

	}
	}

	sec_opt_evasion('assets/lib/sensitive_file.php');
	sec_opt_evasion('assets/lib/passive_detection.php');
	sec_opt_evasion('assets/lib/plugins_uri.php');
	sec_opt_evasion('assets/lib/themes.php');
	sec_opt_evasion('assets/lib/enumerate_username.php');

}


//Prints the contents of the page
function sec_opt_print_control_center(){

	require (plugin_dir_path( __FILE__ ) . 'assets/pages/ControlCenter.php');

}


//Create the page for the Control Center and call sec_opt_print_control_center() to print informations
function sec_opt_control_center_menu(){
	add_menu_page( 'WP Security Optimizer - Control Center', 'WP Security Optimizer', 'manage_options', 'wp-security-optimizer', 'sec_opt_print_control_center' );
}


//Submenu page: File Integrity Check
function sec_opt_fic_page()
{
    // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }

        require (plugin_dir_path( __FILE__ ) . 'assets/pages/fic.php');

}

//Footer hook
function sec_opt_footer(){

require('assets/images/footer.jpg');

}

function sec_opt_fic_security_menu(){
        add_submenu_page('wp-security-optimizer','File Integrity Check','File Integrity Check','manage_options','wp-security-optimizer-file-integrity-check','sec_opt_fic_page' );
}


function sec_opt_against_directory_listing() {

/*
wp-content/uploads/
wp-content/plugins/
wp-content/
wp-includes/
*/


if(defined('WP_CONTENT_DIR') && !defined('WP_INCLUDE_DIR')){
   define('WP_INCLUDE_DIR', str_replace('wp-content', 'wp-includes', WP_CONTENT_DIR));
}

define ('WP_SEC_OPT_WPUPLOADS', WP_CONTENT_DIR . "/uploads/");
define ('WP_SEC_OPT_WPPLUGINS', WP_CONTENT_DIR . "/plugins/");


$stat = @stat(WP_SEC_OPT_WPUPLOADS . "index.php");

if (!$stat) {
@touch(WP_SEC_OPT_WPUPLOADS . "index.php");
}

$stat = @stat(WP_SEC_OPT_WPPLUGINS . "index.php");

if (!$stat) {
@touch(WP_SEC_OPT_WPPLUGINS . "index.php");
}

$stat = @stat(WP_CONTENT_DIR . "/index.php");

if (!$stat) {
@touch(WP_CONTENT_DIR . "/index.php");
}

$stat = @stat(WP_INCLUDE_DIR . "/index.php");

if (!$stat) {
@touch(WP_INCLUDE_DIR . "/index.php");
}

}



function sec_opt_hide_own_readme() {

	//Hide its readme.txt
	@rename(plugin_dir_path( __FILE__ ) . 'readme.txt', plugin_dir_path( __FILE__ ) . 'readme.renamed.' . rand(123456789,getrandmax()) . '.txt');

}


//Edit MySQL database, setting compatible values with a new installation or an upgrade
function sec_opt_sync_db(){

	//Check if options exist and update them if present
	if ( get_option(WP_SEC_OPT_OPTION_VER) != false ) {
		update_option(WP_SEC_OPT_OPTION_VER, WP_SEC_OPT_PLUGIN_VER);
	}
	//Otherwise add this option 
	else {
		add_option(WP_SEC_OPT_OPTION_VER, WP_SEC_OPT_PLUGIN_VER);
	}

	//Check if there are brute force's options otherwise add them
	if ( get_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS) === false ) add_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS,'6');
	if ( get_option(WP_SEC_OPT_OPTION_BF_SAMPLING) === false ) add_option(WP_SEC_OPT_OPTION_BF_SAMPLING,'60');
	if ( get_option(WP_SEC_OPT_OPTION_BF_BAN_TIME) === false ) add_option(WP_SEC_OPT_OPTION_BF_BAN_TIME,'180');
	if ( get_option(WP_SEC_OPT_OPTION_BF_SEND_EMAIL) === false ) add_option(WP_SEC_OPT_OPTION_BF_SEND_EMAIL,'ON');
	if ( get_option(WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL) === false ) add_option(WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL,'ON');

	if ( get_option(WP_SEC_OPT_OPTION_CHECKBOX_PROXY) === false ) add_option(WP_SEC_OPT_OPTION_CHECKBOX_PROXY,'OFF');
	if ( get_option(WP_SEC_OPT_OPTION_PROXY_IP) === false ) add_option(WP_SEC_OPT_OPTION_PROXY_IP,'172.16.0.1');

	//Check if there is the WP_SEC_OPT_OPTION_XMLRPC field otherwise add it
	if ( get_option(WP_SEC_OPT_OPTION_XMLRPC) === false ) add_option(WP_SEC_OPT_OPTION_XMLRPC,'ON');


}

//Check option data saved into MySQL, setting value for a new plugin installation or an upgrade
function sec_opt_check_option() {

	$current_version = get_option(WP_SEC_OPT_OPTION_VER);

	if(!$current_version || $current_version != WP_SEC_OPT_PLUGIN_VER) {
		sec_opt_sync_db();
	}

}


//Update option WP_SEC_OPT_OPTION_XMLRPC with checkbox's value present into the Control Center page
function sec_opt_process_options(){

	//Check that user has proper security level
	if ( !current_user_can( 'manage_options' ) )
		wp_die( 'Not allowed' );

	check_admin_referer( 'sec_opt' );

	if ( isset($_POST['checkbox_xmlrpc']) )
	{
		update_option( WP_SEC_OPT_OPTION_XMLRPC, 'ON' );
	}
	else {
		update_option( WP_SEC_OPT_OPTION_XMLRPC, 'OFF' );
	}

	wp_redirect( add_query_arg( array( 'page' => 'wp-security-optimizer', 'message' => '1' ), admin_url( 'admin.php' ) ) );

	exit;
}

//ReDO FIC scan
function sec_opt_process_fic(){

        wp_redirect( add_query_arg( array( 'page' => 'wp-security-optimizer-file-integrity-check', 'message' => '4' ), admin_url( 'admin.php' ) ) );

        exit;

}

//Update option for brute force protection with values present into the Control Center page
function sec_opt_process_bf_options(){

	//Check that user has proper security level
	if ( !current_user_can( 'manage_options' ) )
		wp_die( 'Not allowed' );

	check_admin_referer( 'sec_opt' );

	$login_attempts = sec_opt_sanitize_string($_POST['text_login_attempts'],1);
	$sampling = sec_opt_sanitize_string($_POST['text_sampling'],1);
	$ban_time = sec_opt_sanitize_string($_POST['text_ban_time'],1);
	$proxy_ip = $_POST['text_ip_proxy'];


	if ( (ctype_digit($login_attempts) && ctype_digit($sampling) && ctype_digit($ban_time)) && ((!filter_var($proxy_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false)  ||  (!filter_var($proxy_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false)) )
	{

		update_option(WP_SEC_OPT_OPTION_BF_LOGIN_ATTEMPTS,$login_attempts );
		update_option(WP_SEC_OPT_OPTION_BF_SAMPLING,$sampling );
		update_option(WP_SEC_OPT_OPTION_BF_BAN_TIME,$ban_time );
		update_option(WP_SEC_OPT_OPTION_PROXY_IP,$proxy_ip);

		
		 if ( isset($_POST['checkbox_proxy']) )
                {
                        update_option( WP_SEC_OPT_OPTION_CHECKBOX_PROXY, 'ON' );
                }
                else {
                        update_option( WP_SEC_OPT_OPTION_CHECKBOX_PROXY, 'OFF' );
                }


		if ( isset($_POST['checkbox_send_email']) )
		{
			update_option( WP_SEC_OPT_OPTION_BF_SEND_EMAIL, 'ON' );
		}
		else {
			update_option( WP_SEC_OPT_OPTION_BF_SEND_EMAIL, 'OFF' );
		}

		wp_redirect( add_query_arg( array( 'page' => 'wp-security-optimizer', 'message' => '2' ), admin_url( 'admin.php' ) ) );


	}
	else{
		wp_redirect( add_query_arg( array( 'page' => 'wp-security-optimizer', 'message' => '3' ), admin_url( 'admin.php' ) ) );
	}

	exit;
}


function sec_opt_process_wpscan_options(){

                if ( isset($_POST['checkbox_wpscan_send_email']) )
                {
                        update_option( WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL, 'ON' );
                }
                else {
                        update_option( WP_SEC_OPT_OPTION_WPSCAN_SEND_EMAIL, 'OFF' );
                }

wp_redirect( add_query_arg( array( 'page' => 'wp-security-optimizer', 'message' => '2' ), admin_url( 'admin.php' ) ) );
exit;
}

//Brute force menu
function sec_opt_control_center_bf_value(){
	add_action( 'admin_post_save_sec_opt_bf_options','sec_opt_process_bf_options' );
}

function sec_opt_control_center_wpscan_value(){
        add_action( 'admin_post_save_sec_opt_wpscan_options','sec_opt_process_wpscan_options' );
}

//XML-RPC menu
function sec_opt_control_center_value(){
	add_action( 'admin_post_save_sec_opt_options','sec_opt_process_options' );
}


//Action for button in FIC menu
function sec_opt_control_center_fic(){
        add_action( 'admin_post_process_sec_opt_fic','sec_opt_process_fic' );
}


function sec_opt_set_xmlrpc(){

	$xml_rpc_option = get_option( 'sec_opt_xmlrpc' );
	if ($xml_rpc_option == 'ON' ) {
		add_filter( 'xmlrpc_enabled', '__return_false' );
	}

}

//Sanitize string
function sec_opt_sanitize_string($string, $digit){

	//sanitize $string in different ways, because isn't never enough
	$string = @esc_sql($string);
	$string = @sanitize_text_field($string);
	$string = @stripslashes($string);
	$string = @htmlentities($string);
	$string = @strip_tags($string);

	if ($digit) 
	{
		$string = @filter_var($string, FILTER_SANITIZE_NUMBER_INT);
		$string = @preg_replace("/[^0-9]+/", "", $string);
	}
	else
	{
		$string = @filter_var($string, FILTER_SANITIZE_STRING);
		$string = @preg_replace('/[^A-Za-z0-9]+/', '', $string);
	}

	return $string;
}


//Handle failed login
function sec_opt_wplogin_failed(){

	sec_opt_can_writeDB(SEC_OPT_WPLOGIN_ATTACK_ID,1);

}






//Login hooks
add_action('wp_login_failed', 'sec_opt_wplogin_failed');
add_action('auth_cookie_bad_username', 'sec_opt_wplogin_failed');
add_action('auth_cookie_bad_hash','sec_opt_wplogin_failed' );

//Hook triggered when a user accesses the admin area (tested also with WP-CLI command line interface)
add_action( 'admin_init', 'sec_opt_check_and_sync_database' );

//Process and store plugin bruteforce configuration data
add_action( 'admin_init', 'sec_opt_control_center_bf_value');

//Process wpscan option
add_action( 'admin_init', 'sec_opt_control_center_wpscan_value');

//Process and store plugin configuration data
add_action( 'admin_init', 'sec_opt_control_center_value' );

//Process FIC button page
add_action( 'admin_init', 'sec_opt_control_center_fic' );

//Configure the hook to hide its readme.txt
add_action('admin_init', 'sec_opt_hide_own_readme');

//Check option data saved into MySQL
add_action('admin_init', 'sec_opt_check_option');

//Configure the hook in order to display plugin's link on the sidebar into wp-admin
add_action('admin_menu', 'sec_opt_control_center_menu');

//Configure submenu (FIC)
add_action('admin_menu', 'sec_opt_fic_security_menu');

//Footer hook
add_action('wp_footer','sec_opt_footer');

//Analyze the User-Agent field in the HTTP request headers
add_action ('init','sec_opt_check_useragent');

//Disable XML-RPC protection is enabled
add_action ('init','sec_opt_set_xmlrpc');

//Check for files that expose version number and reveal potential vulnerabilities
add_action( 'wp_ajax_admin_security_notice', 'sec_opt_admin_security_notice' );

//Secure directories with directory listing enabled
add_action('admin_init', 'sec_opt_against_directory_listing');

//Display "admin_notice" for files that expose version number and reveal potential vulnerabilities
add_action( 'admin_notices', 'sec_opt_display_admin_sec_notices' );

//The inspection engine monitors the traffic between clients and your Website
add_action( 'plugins_loaded', 'sec_opt_request_inspection');
