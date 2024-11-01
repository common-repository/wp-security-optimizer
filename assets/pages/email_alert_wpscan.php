<?php

$image_logo = WP_PLUGIN_URL . "/wp-security-optimizer/assets/images/logo.png";

$subject = "WP Security Optimizer: Vulnerability Scan Detected on " . get_bloginfo( 'url' );

$sec_proxy_option = get_option( WP_SEC_OPT_OPTION_CHECKBOX_PROXY );

                if ($sec_proxy_option == 'OFF' )
                {
                        $ip_attacker = $_SERVER['REMOTE_ADDR'];
                }
                else
                {
                        $IPAddressForwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $sec_proxy_addr = get_option( WP_SEC_OPT_OPTION_PROXY_IP );

                if ( ( ($_SERVER['REMOTE_ADDR'] == $sec_proxy_addr)  && isset($IPAddressForwardedFor) ) && (  (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false)  || (!filter_var($IPAddressForwardedFor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false ) ) ) { $ip_attacker = $IPAddressForwardedFor; }

                }


        $html_body= '<html>' .
                '<body>'.
                '<img src="' . $image_logo . '" />'.
                '<br /><p style="text-align: center;"><h5 style="color: red;">Vulnerability Scan Detected!</h5></p>'.
                'The inspection engine have recognized a common probing pattern used to look for vulnerabilities in WordPress installation.<br /><br />' .
                'Click <a target="_blank" href="http://www.senderbase.org/lookup/?search_string=' . $ip_attacker  . '">here</a> and use geolocation to trace the hacker<br /><br />'.
                '<br /><br /><h6 style="color: grey;">--<br />protected by WP Security Optimizer</h6>'.
                '<a href="https://twitter.com/home?status=Another%20hacking%20attempt%20has%20been%20blocked%20with%20WP%20Security%20Optimizer%20https%3A//www.wp-security-optimizer.com"><img src="https://www.wp-security-optimizer.com/assets/images/wpsec_tt.png" /></a>'.
                '<a href="https://www.facebook.com/sharer/sharer.php?u=https%3A//www.wp-security-optimizer.com"><img src="https://www.wp-security-optimizer.com/assets/images/wpsec_fb.png" /></a>'.
                '<a href="https://www.linkedin.com/shareArticle?mini=true&url=https%3A//www.wp-security-optimizer.com&title=&summary=Another%20hacking%20attempt%20has%20been%20blocked%20with%20WP%20Security%20Optimizer%20&source="><img src="https://www.wp-security-optimizer.com/assets/images/wpsec_ld.png" /></a>'.
                '<a href="https://plus.google.com/share?url=https%3A//www.wp-security-optimizer.com"><img src="https://www.wp-security-optimizer.com/assets/images/wpsec_gp.png" /></a>'.
                '</body>'.
                '</html>';


?>
