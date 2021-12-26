<?php
/**
 * WRAT | WordPress REST Auth Token
 * oAuth2 implementation for WordPress REST API
 * 3.0.0 (Beta)
 * 
 * https://github.com/imjafran/wrat
 *
 * Jafran Hasan
 * https://github.com/imjafran
 * 
 * License MIT
 * 
 * Learn more about this SDK ./README.md
 */
  
defined('ABSPATH') or die('Direct Script not Allowed');

if (!class_exists("WRAT")) {

    // core wrat class 

    final class WRAT
    { 

        public static $instance = null;

        public static function init()
        {
            if(!self::$instance) {
                $instance = new self;
                
                $instance->register_hooks();
                self::$instance = $instance;
            } 
        }

        # init wrat
        function register_hooks()
        { 
            add_action('rest_api_init', [$this, 'init_oauth2'], 0);
            add_action('rest_api_init', [$this, 'apply_cors'], 0);
            add_action('rest_api_init', [$this, 'register_rests'] );
        }
 
        # create token
        function create_token($length = 12)
        {
            return 'wrat.' . time() . '.' . bin2hex( random_bytes( $length ) );
        }

        # get wrat from header || request
        function get_wrat()
        {
            $token = false;
            $headers = $_SERVER["HTTP_AUTHORIZATION"] ?? false;
            if ($headers) {
                preg_match("/wrat.[^\s]+/im", $headers, $match);
                if ($match && !empty($match) && count($match) > 0) {
                    $token = trim(str_replace('WRAT ', '', $match[0]));
                }
            }
            if (!$token) {
                $inputs = @file_get_contents('php://input');
 
                $params = json_decode($inputs); 

                if($params){
                    $token = $params->wrat ?? $params->token ?? null;
                } else {
                    preg_match("/wrat=.[^\s]+/im", $inputs, $match);
                    if (!empty($match)) {
                        $token = trim(str_replace('wrat=', '', $match[0]));
                    } 
                } 
            }

            if (!$token) {
                $token = $_REQUEST['wrat'] ?? false;
            }

            return sanitize_text_field( $token );
        } 

        # Get user token, create otherwise
        function get_user_token($user_id = false, $force = false)
        {
            $user_id = $user_id ?? get_current_user_id();
            
            # parse old token
            $token = get_user_meta( $user_id, 'wrat_token', true );

            # create new token
            if(!$token || empty($token) || $force === true) {
                $token = $this->create_token();
                update_user_meta( $user_id, 'wrat_token', $token );
            }

            return $token;
            
        } 

        # get user from token

        function get_user_by_wrat($token = null)
        {
            if(!$token) $token = $this->get_wrat();
            if(!$token) return false;
 
            global $wpdb;
            $sql = $wpdb->prepare("SELECT user_id FROM {$wpdb->prefix}usermeta WHERE `meta_key` = 'wrat_token' AND meta_value = %s", $token);
            $result = $wpdb->get_row($sql);

            if(!$result) return false;

            $user = get_user_by( 'id', $result->user_id ); 

            return $user ?? false;
        }


        # get user data from user object
        function get_user($user = null)
        { 
            $user = $user ?? get_current_user_id();

            if ( !$user instanceof \WP_User ) {
                if(is_numeric($user)) $user = get_user_by( 'id', $user );
                else $user = get_current_user();
            }  

            $first_name = get_user_meta($user->data->ID, 'first_name', true);
            $last_name = get_user_meta($user->data->ID, 'last_name', true);

            $data = (object) [];
            $data->id = (int) $user->data->ID;
            $data->first_name = $first_name;
            $data->last_name = $last_name;
            $data->email = $user->data->user_email;
            $data->role = $user->roles[0];
 
            $data->token =  $this->get_user_token($user->data->ID);

            return apply_filters( 'wrat_user_data', $data );
        }

        # init oauthentication2
        function init_oauth2()
        { 

            $user_id = get_current_user_id();
            
            if(!$user_id) $user_id = $this->get_user_by_wrat();

            if($user_id && $user_id > 0) { 
                # authenticated
                wp_set_current_user($user_id);

            } else {

                # check wrat mode, if routes are whitelisted by default
                $blacklist_endpoints= apply_filters( 'wrat_blacklist_endpoints', true );
    
                # check route resctriction
                $endpoint_matched = $this->endpoint_matched();
 
                if ($blacklist_endpoints && $endpoint_matched || !$blacklist_endpoints && !$endpoint_matched) {
                    wp_send_json([
                        'success' => false, 
                        'message' => 'invalid_wrat'
                    ]);
                    wp_die();
                }

            } 
           
        }

        # check whether the route is matched to registered endpoints
        function endpoint_matched()
        {

            $parsed_url = $_SERVER['REQUEST_URI'] ?? '/';
            $parsed_url = explode('?', $parsed_url)[0];
            $requested_url = trim($parsed_url, '/');            

            $wrat_endpoints = apply_filters('wrat_endpoints', []);

            $wrat_prefix = apply_filters( 'wrat_endpoint_prefix', '' );
            
            if(!empty($wrat_endpoints)){
                foreach ($wrat_endpoints as $wrat_endpoint) {
                    
                    # building requested uri
                    $wrat_endpoint = $wrat_prefix . 'wp-json/' . trim($wrat_endpoint, '/');

                    # making ready for regular expression matching
                    $wrat_endpoint = str_replace(['*'], ['.+'], $wrat_endpoint);

                    preg_match('~^' . $wrat_endpoint . '+$~', $requested_url, $match);
 
                    if ($match[0]) return $match[0]; 
                }
            } 

            return false;
        }


        # Registering Endpoints
        function register_rests($server)
        {

            $routes = [ 
                ['auth', ['POST'], 'rest_authenticate_user'], 
                ['verify', ['GET', 'POST'], 'rest_verify_token'],
            ];

            foreach ($routes as $route) {
                register_rest_route('/wrat', $route[0], [
                    'methods'  => $route[1],
                    'callback' => [$this, $route[2]]
                ]);
            }
        }

        # Authenticate user
        function rest_authenticate_user($request)
        {
            $input = (object) $request;

            # Before WRAT login
            do_action('wrat_before_auth'); 

            # request inputs
            $email = sanitize_text_field( $input->email ?? '' );
            $username = sanitize_text_field( $input->username ?? '' );
            $password = sanitize_text_field( $input->password ?? '' );

            # No email
            if( empty($email) ){
                return new WP_REST_Response(['success' => false, 'code' => 'invalid_email']);
            }
            # No username or email
            if(empty($email) && empty($username)){
                return new WP_REST_Response(['success' => false, 'code' => 'invalid_username']);
            }

            # No password
            if( empty($password) ){
                return new WP_REST_Response(['success' => false, 'code' => 'incorrect_password']);
            }

            # authenticate
            $authenticated = wp_authenticate($email ?? $username, $password);

            # authenticate error
            if ($authenticated->data == null) {

                $errors = array_map(function ($error) {
                    return $error;
                }, array_keys($authenticated->errors));

                # failed auth
                do_action('wrat_auth_failed', $email, $username, $errors);

                return new WP_REST_Response(['success' => false, 'code' => $errors[0]]);
            }

            # auth success 
            $user = $this->get_user($authenticated); 

            # after wat auth hook 
            do_action('wrat_after_auth', $user->id);

            return new WP_REST_Response(['success' => true, 'user' => $user]);
        } 


        # verify wrat

        function rest_verify_token()
        {  
            $user = $this->get_user_by_wrat(); 

            if($user) {
                return new WP_REST_Response([
                    'success' => true,
                    'user' => $this->get_user($user)
                ]);
            }

            return new WP_REST_Response([
                'success' => false,
                'code' => 'invalid_wrat'
            ]);
        }


        # enable cors 
        public function apply_cors()
        {
            $urls = apply_filters( 'wrat_cors', '*' );

            header('Access-Control-Allow-Origin: ' . $urls);
            header('Access-Control-Allow-Methods: ' . $urls);
            header("Access-Control-Allow-Credentials: true");
            header('Content-Type: ' . $urls);
            header('Access-Control-Allow-Headers: Origin, Authorization, Content-Type, x-xsrf-token, x_csrftoken, Cache-Control, X-Requested-With');
        }
    }  
    
    # user defined functions

    # get user wrat
    if( !function_exists('wrat_get_token') ){       
        function wrat_get_token($user_id = null){
            $_wrat = new WRAT();
            return $_wrat->get_user_token($user_id);
        }
    }

    # get user
    if( !function_exists('wrat_get_user') ){       
        function wrat_get_user($user_id = null){
            $_wrat = new WRAT();
            return $_wrat->get_user($user_id);
        }
    }

}

/**
 * Thanks for using WRAT
 */
