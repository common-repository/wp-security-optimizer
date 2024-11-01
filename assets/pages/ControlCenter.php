<?php

/* Block direct access */
if (!defined('ABSPATH')) {
        die('Direct access not allowed!');
}

?>

<style type="text/css">

div.box
{
width: 360px;
padding: 10px;
border: 1px solid #d0c9c9;
border-radius: 10px;
-moz-border-radius: 10px;
}

#parent {
overflow: hidden;
border: 0px solid red
}
.right {
float: left;
width: 360px;
height: 590px;
margin: 1px 5px;
display: inline;
overflow-x: auto;

}
.left {
float: left;
overflow-x: auto;
width: 360px;
height: 590px;
margin: 1px 5px;
display: inline;
}

.right_down {
float: left;
width: 360px;
height: 540px;
margin: 1px 5px;
display: inline;
overflow-x: auto;

}
.left_down {
float: left;
overflow-x: auto;
width: 360px;
height: 540px;
margin: 1px 5px;
display: inline;
}


</style>


<div id="parent">

<div style="background-color:#0073aa; width:760px; padding: 10px; color: white;">


<?php
$image_logo = WP_PLUGIN_URL . "/wp-security-optimizer/assets/images/logo.png";
echo '<img src="' . $image_logo . '" />';
?>


</div>

<br />

<?php if ( isset( $_GET['message'] ) && ( $_GET['message'] == '1' || $_GET['message'] == '2' )) { ?>
<div id='message' style='width:120px;' class='updated fade'><p><strong>Settings Saved</strong></p></div>
<br />
<?php } ?>

<?php if ( isset( $_GET['message'] ) && $_GET['message'] == '3' ) { ?>
<div id='message' style='width:120px;' class='error fade'><p><strong>Wrong settings</strong></p></div>
<br />
<?php } ?>



    <div class="left box">
<u style="color: #0073aa;">General Settings:</u>
<hr style="color: #0073aa; border-width: 2px; margin-top: 0.5em; margin-bottom: 1.5em; border-style: inset; margin-left: auto; margin-right: auto;">
<!-- Protection is always active -->
<span>Protection: <h4 style="display: inline; color: green; position:relative; right:-2em;">Active</h4></span>
<hr style="border-width: 1px; margin-top: 0.5em; margin-bottom: 1.5em; border-style: inset; margin-left: auto; margin-right: auto;">
<span>E-mail Alerts: <h4 style="display: inline; color: green; position:relative; right:-1.1em;">
<?php
echo get_bloginfo('admin_email');
?>

</h4>


<?php
$sec_opt_jquery = WP_PLUGIN_URL . "/wp-security-optimizer/assets/pages/morris/jquery.min.js";
$sec_opt_raphael = WP_PLUGIN_URL . "/wp-security-optimizer/assets/pages/morris/raphael-min.js";
$sec_opt_morris = WP_PLUGIN_URL . "/wp-security-optimizer/assets/pages/morris/morris.js";
$sec_opt_prettify = WP_PLUGIN_URL . "/wp-security-optimizer/assets/pages/morris/prettify.min.js";
$sec_opt_example = WP_PLUGIN_URL . "/wp-security-optimizer/assets/pages/morris/lib/example.js";
?>

<script src=<?php echo "\"$sec_opt_jquery\"" ?>></script>
  <script src=<?php echo "\"$sec_opt_raphael\"" ?> ></script>
  <script src=<?php echo "\"$sec_opt_morris\"" ?> ></script>
  <script src=<?php echo "\"$sec_opt_prettify\"" ?> ></script>
  <script src=<?php echo "\"$sec_opt_example\"" ?> ></script>
  <link rel="stylesheet" href=<?php echo "\"$sec_opt_example\"" ?> >
  <link rel="stylesheet" href=<?php echo "\"$sec_opt_prettify\"" ?> >
  <link rel="stylesheet" href=<?php echo "\"$sec_opt_morris\"" ?> >

<br />
<br />
<span><h3>Attacks Blocked</h3></span>
<hr>

<div id="graph"></div>
<script>
Morris.Bar({
element: 'graph',
data: [


<?php

global $wpdb;

$table_name = $wpdb->prefix . 'sec_opt_counter';

$result = $wpdb->get_results ( "SELECT total_xmlrpc_attack FROM `$table_name` WHERE id='1';" );

foreach ( $result as $page )
{
   $xmlrpc_counter = $page->total_xmlrpc_attack;
}

$result = $wpdb->get_results ( "SELECT total_bruteforce_attack FROM `$table_name` WHERE id='1';" );

foreach ( $result as $page )
{
   $bruteforce_counter = $page->total_bruteforce_attack;
}

$result = $wpdb->get_results ( "SELECT total_wpscan_attack FROM `$table_name` WHERE id='1';" );

foreach ( $result as $page )
{
 $wpscan_counter = $page->total_wpscan_attack; 
}

$result = $wpdb->get_results ( "SELECT total_badbot_attack FROM `$table_name` WHERE id='1';" );

foreach ( $result as $page )
{
  $badbot_counter = $page->total_badbot_attack;
}

?>

{x: '', y: <?php echo $xmlrpc_counter; ?>, z: <?php echo $wpscan_counter; ?>, a: <?php echo $bruteforce_counter; ?>, b :<?php echo $badbot_counter; ?>}
],
xkey: 'x',
ykeys: ['y', 'z', 'a','b'],
labels: ['XML RPC', 'WPScan', 'WP Login','Malware']
})

</script>

 <table style="width:100%">
  <tr>
    <td style='color:#0b62a4;' width="30%">XML-RPC:</td>
    <td style='color:#0b62a4;'><?php echo $xmlrpc_counter; ?></td>
  </tr>
  <tr>
    <td style='color:#7a92a3;' width="30%">WPScan:</td>
    <td style='color:#7a92a3;'><?php echo $wpscan_counter; ?></td>
  </tr>
  <tr>
    <td style='color:#4da74d;' width="30%">WP Login:</td>
    <td style='color:#4da74d;'><?php echo $bruteforce_counter; ?></td>
  </tr>
  <tr>
    <td style='color:#fe8a1b;' width="30%">Malware:</td>
    <td style='color:#fe8a1b;'><?php echo $badbot_counter; ?></td>
  </tr>
</table> 



<h6>Massive attacks can exhaust your database's resources. In order to avoid this problem, counters for the same attacker's IP will be handled with a session timeout</h6>

<?php

global $wpdb;

$table_name = $wpdb->prefix . 'sec_opt_attack_history';

$result = $wpdb->get_results ( "SELECT IP_attacker FROM `$table_name` ORDER BY last_seen_timestamp DESC limit 1;" );

foreach ( $result as $page )
{
echo "<span style='color:red;'>Latest attack from: </span>";
echo '<a target="_blank" href="http://www.senderbase.org/lookup/?search_string=' . $page->IP_attacker  . '">' . $page->IP_attacker . '</a>';
}


?>


</div>

    <div class="right box">
<h2>WPScan protection</h2>
<span>Evasion rules for WPScan's plugins database: <h4 style="display: inline; color: green; position:relative; right:-4em;"> 

<?php
$lines = file(plugin_dir_path( __FILE__ ) . '../lib/plugins_uri.php');
echo count($lines)-4;
?>

</h4></span>
<hr style="border-width: 1px; margin-top: 0.5em; margin-bottom: 1.5em; border-style: inset; margin-left: auto; margin-right: auto;">
<span>Evasion rules for WPScan's themes database: <h4 style="display: inline; color: green; position:relative; right:-4.5em;">

<?php
$lines = file(plugin_dir_path( __FILE__ ) . '../lib/themes.php');
echo count($lines)-4;
?>

<!-- All features are always enabled, by default -->
</h4></span>
<hr style="border-width: 1px; margin-top: 0.5em; margin-bottom: 1.5em; border-style: inset; margin-left: auto; margin-right: auto;">
<span>Block Username Enumeration:  <h4 style="display: inline; color: green; position:relative; right:-10em;"> Active</h4></span>
<hr style="border-width: 1px; margin-top: 0.5em; margin-bottom: 1.5em; border-style: inset; margin-left: auto; margin-right: auto;">
<span>Scan Avoidance Technology:   <h4 style="display: inline; color: green; position:relative; right:-10.75em;"> Active</h4></span>
<hr style="border-width: 1px; margin-top: 0.5em; margin-bottom: 1.5em; border-style: inset; margin-left: auto; margin-right: auto;">
<span>Block Malicious User Agent:  <h4 style="display: inline; color: green; position:relative; right:-10.95em;"> Active</h4></span>
<hr style="border-width: 1px; margin-top: 0.5em; margin-bottom: 1.5em; border-style: inset; margin-left: auto; margin-right: auto;">
<span>Sensitive Data Discovery: <h4 style="display: inline; color: green; position:relative; right:-12.25em;"> Active</h4></span>

<br /><br />
<br />

<form method="post" action="admin-post.php">

<input type="hidden" name="action" value="save_sec_opt_wpscan_options" />

<span  style="margin-right:12px;">Email Alerting</span> <input type="checkbox" style="padding-bottom:20px;" name="checkbox_wpscan_send_email" 

<?php
$bf_send_email = get_option( 'sec_opt_wpscan_send_email' );
if ($bf_send_email == 'ON' ) echo ' checked="checked" ';
?>

/><br />

<div align="right"><input type="submit" value="Save" class="button-primary"/></div>

</form>

<br />
<br />
<br />
<div align="center">
<?php
$image_logo = WP_PLUGIN_URL . "/wp-security-optimizer/assets/images/wpscan-protection.png";
echo "<img src=\"". $image_logo . "\" />";
?>
</div>

<?php if ( isset( $_GET['message'] ) && ( $_GET['message'] == '1' || $_GET['message'] == '6' )) { ?>
<div id='message' style='width:120px;' class='updated fade'><p><strong>Settings Saved</strong></p></div>
<br />
<?php } ?>

</div>
</div>
<br />





<div id="sec_opt_xmlrpc" class="left_down box">

<h2>XML RPC information</h2>
WordPress's XML-RPC function allows external applications (such of Mobile App) to interact and edit your site's content.
<br />
It's mainly used for password cracking and dDoS attack, therefore it's recommended that you disable this service enabling the following protection:
<br />
<br />
<br />
<br />
<form method="post" action="admin-post.php">

<input type="hidden" name="action" value="save_sec_opt_options" />

<!-- Adding security through hidden referrer field -->
<?php wp_nonce_field( 'sec_opt' ); ?>

<br />
<br />

<span>XML-RPC Protection: </span><input type="checkbox" name="checkbox_xmlrpc" 

<?php 
$xml_rpc_option = get_option( 'sec_opt_xmlrpc' );
if ($xml_rpc_option == 'ON' ) echo ' checked="checked" ';
?>

/>

<div align="right"><input type="submit" value="Save" class="button-primary"/></div>


</form>

<br />
<br />
<br />
<br />
<div align="center">
<?php
$image_xmlrpc = WP_PLUGIN_URL . "/wp-security-optimizer/assets/images/xmlrpc-protection.png";
echo "<img src=\"". $image_xmlrpc . "\" />";
?>
</div>

</div>



<div id="sec_opt_xmlrpc" class="right_down box">

<h2>Brute Force Protection</h2>
Brute Force attack is a hacking tecnique used to gain access to your site: The attacker, consuming your web server resources, guesses username and password combinations until he finds one that works.
<br />
<br />
<form method="post" action="admin-post.php">

<input type="hidden" name="action" value="save_sec_opt_bf_options" />

<!-- Adding security through hidden referrer field -->
<?php wp_nonce_field( 'sec_opt' ); ?>


 <table style="width:100%">
  <tr>
    <td width="30%">Failed Logins:</td>
    <td>

<input type="text" maxlength="3" size="3" name="text_login_attempts" value="

<?php
echo get_option( 'sec_opt_bruteforce_login_attempts' );
?>

" />

</td>
  </tr>
  <tr>
    <td width="30%">Time Interval:</td>
    <td>

<input type="text" maxlength="3" size="3" name="text_sampling" value="

<?php
echo get_option( 'sec_opt_bruteforce_sampling');
?>

" />

</td>
  </tr>
  <tr>
    <td  width="30%">Banning Time:</td>
    <td>

<input type="text" maxlength="3" size="3" name="text_ban_time" value="

<?php
echo get_option( 'sec_opt_bruteforce_ban_time');
?>

" />

</td>
  </tr>


<tr>
    <td  width="30%">Email Alerting</td>
    <td>

<input type="checkbox" style="padding-bottom:20px;" name="checkbox_send_email" 

<?php
$bf_send_email = get_option( 'sec_opt_bruteforce_send_email' );
if ($bf_send_email == 'ON' ) echo ' checked="checked" ';
?>

/>

</td>
  </tr>
</table>





<br />
<br />
<span  style="margin-right:1em; font-size: 15px;"><b>Advanced configuration</b></span><br /><br />
Wordpress blog/site behind a reverse proxy
<br />
<br />


<table style="width:100%">
  <tr>
    <td width="30%">Enable Proxy</td>
    <td>


 <input type="checkbox" name="checkbox_proxy" 

<?php
$sec_opt_behind_proxy = get_option( 'sec_opt_proxy' );
if ($sec_opt_behind_proxy == 'ON' ) echo ' checked="checked" ';
?>

/>

</td>
  </tr>
  <tr>
    <td width="30%">Proxy IP Address</td>
    <td>

<input type="text" maxlength="15" size="8" name="text_ip_proxy" value="

<?php
echo get_option( 'sec_opt_proxy_ip');
?>

" />


</td>
  </tr>
</table>


<h6>Replaces the original client IP address (Proxy IP Address) for the connection with the IP address presented by X-Forwarded-For header</h6>



<div align="right"><input type="submit" value="Save" class="button-primary"/></div>

</form>

</div>
