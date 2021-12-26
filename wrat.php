<?php

/**
 *
 * @package wrat
 *
 * Plugin Name: WRAT | WordPress REST Auth Token
 * Plugin URI: https://github.com/imjafran/wrat
 * Description: oAuth2 Implementation for WordPress REST API
 * Version: 3.0.0
 * Author: Jafran Hasan
 * Author URI: https://github.com/imjafran
 * License: GPLv3 or latter
 * Text Domain: wrat
 */

namespace WRAT;

use \WP_REST_Response;

defined('ABSPATH') or die('Direct Script not Allowed');

if (!class_exists("\WRAT\WRAT")) {

    // core wrat class 

    final class WRAT
    {
 
        public $extended = '/'; 

        # init wrat
        function init()
        {
            $this->extended = str_replace('/index.php', '', $_SERVER['PHP_SELF']);

            $this->register_hooks();
        }

         
        # register hooks 
        function register_hooks()
        {  
            # custom construct method        
            add_action('rest_api_init',                         [$this, 'wrat_rest_init'], 0);
            add_action('rest_api_init',                         [$this, 'register_wrat_rests'], 0);
        }

        # get inputs from request
        function inputs()
        {            
            try {
                $json = file_get_contents('php://input');
                $request = json_decode(sanitize_text_field($json));
            } catch(\Exception $e) {
                
            }

            if(!$request || empty($request)) {
                $request =  $_REQUEST;
            }  

            return (object) $request;
        }
        
        # create token
        function create_wrat_token($length = 12)
        {
            return 'wrat.' . time() . '.' . bin2hex( random_bytes( $length ) );
        }

        # get wrat from header || request
        function get_wrat_request()
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
                $token = $this->create_wrat_token();
                update_user_meta( $user_id, 'wrat_token', $token );
            }

            return $token;
            
        } 

        # get user from token

        function get_user_by_wrat($token = null)
        {
            if(!$token) $token = $this->get_wrat_request();
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

        # verify authentication
        function wrat_rest_init()
        { 

            $user_id = get_current_user_id();
            
            if(!$user_id) $user_id = $this->get_user_by_wrat();

            if($user_id && $user_id > 0) { 
                wp_set_current_user($user_id);
            }

            # check route resctriction
            if ($this->is_route_resctricted() && !is_user_logged_in()) {
                wp_send_json($this->error('invalid_wrat'));
                wp_die();
            }
        }

        # check whether the route is restricted for logged-in users
        function is_route_resctricted()
        {

            $parsed_url = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
            $parsed_url = explode('?', $parsed_url)[0];
            $requested_url = trim(str_replace(home_url(), '', $parsed_url), '/');            

            $wrat_endpoints = apply_filters('wrat_endpoints',  []);
           
            $restricted = false;
            
            if(!empty($wrat_endpoints)){
                foreach ($wrat_endpoints as $wrat_endpoint) {
                    $wrat_endpoint = trim($wrat_endpoint, '/');
                    $wrat_endpoint = str_replace(['*'], ['.+'], $wrat_endpoint);
                    preg_match('~^' . $wrat_endpoint . '+$~', $requested_url, $match);
                    if ($match[0]) {
                        $restricted = $match[0];
                        break;
                    }
                }
            } 

            return $restricted;
        }


        # Registering Endpoints
        function register_wrat_rests($server)
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
            $email = $input->email ?? null;
            $username = $input->username ?? null;
            $password = $input->password ?? null;

            # No email
            if(!$email){
                return new WP_REST_Response(['success' => false, 'code' => 'invalid_email']);
            }
            # No username or email
            if(!$email && !$username){
                return new WP_REST_Response(['success' => false, 'code' => 'invalid_username']);
            }

            # No password
            if(!$password){
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
    }

    # init wrat class
    $_wrat = new WRAT();
    $_wrat->init();
 

    # user defined functions

    # get user wrat
    if( !function_exists('wrat_get_token') ){       
        function wrat_get_token($user_id = null){
            $_wrat = new \WRAT\WRAT();
            return $_wrat->get_user_token($user_id);
        }
    }

    # get user
    if( !function_exists('wrat_get_user') ){       
        function wrat_get_user($user_id = null){
            $_wrat = new \WRAT\WRAT();
            return $_wrat->get_user($user_id);
        }
    }

}


