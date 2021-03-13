<?php

/**
 *
 * @package wrat
 *
 * Plugin Name: WRAT | WordPress REST Auth Token
 * Plugin URI: https://github.com/imjafran/wrat
 * Description: oAuth2 Implementation for WordPress REST API, Specially Mobile Application
 * Version: 1.0.0
 * Author: Jafran Hasan
 * Author URI: https://github.com/iamjafran
 * License: GPLv3 or latter
 * Text Domain: wrat
 */


namespace WRAT;

use \WP_REST_Response;

defined('ABSPATH') or die('Direct Script not Allowed');

if (!class_exists("\WRAT\WRAT")) {
    class WRAT
    {

        # member variables
        public $dir = '';
        public $path = '';
        public $extended = '/';
        private $table = 'wrat_tokens';

        function __construct()
        {
            $this->dir = plugin_dir_url(__FILE__);
            $this->path = plugin_dir_path(__FILE__);
            $this->extended = str_replace('/index.php', '', $_SERVER['PHP_SELF']);
        }

        # Register Hooks 
        function init()
        {
            # installation hooks
            register_activation_hook(__FILE__,                  [$this, 'wrat_activate_plugin']);
            register_deactivation_hook(__FILE__,                [$this, 'wrat_deactivate_plugin']);

            # custom construct method       
            add_action('plugins_loaded',                        [$this, 'after_wat_loaded']);
            add_action('rest_api_init',                         [$this, 'wat_rest_init'], 0);
            add_action('rest_api_init',                         [$this, 'register_wrat_rests']);
            add_action('wrat_after_registration',                [$this, 'wrat_after_registration'], 0);
        }

        // activation 
        public function wrat_activate_plugin()
        {
            // create tables 
            global $wpdb;
            $table_name = $wpdb->prefix . $this->table;

            $charset_collate = $wpdb->get_charset_collate();

            $sql = "CREATE TABLE $table_name (
                id mediumint(9) NOT NULL AUTO_INCREMENT,
                user_id mediumint(9) NOT NULL,
                token varchar(250) NOT NULL,
                created datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
                validity datetime DEFAULT NULL,
                PRIMARY KEY (id)
            ) $charset_collate;";

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);
        }

        // deactivation 
        public function wrat_deactivate_plugin()
        {
            // do nothing 
        }


        function getMessages($message_id = false)
        {
            $messages = [
                'empty_username' => 'Empty Username',
                'not_registered' => 'User not Registered',
                'invalid_username' => 'Invalid Username',
                'invalid_email' => 'Invalid Email',
                'empty_password' => 'Empty Password',
                'incorrect_password' => 'Incorrect Password',
                'existing_user_email' => 'Email already registered',
                'user_does_not_exist' => 'User doesn\'t exist',
                'not_allowed' => 'Not Allowed',
                'reset_email_sent' => 'Password Recovery Email Sent',
                'user_registered' => 'User Registered Successfully',
                'valid_web_auth_token' => 'Valid Web Auth Token',
                'invalid_web_auth_token' => 'Invalid Web Auth Token',
                'logged_in' => 'Logged In',
                'password_changed' => 'Password changed successfully',
            ];

            $FilteredMessages = apply_filters('wat_response_messages', $messages);

            return (array_key_exists(strtolower($message_id), $FilteredMessages)) ? $FilteredMessages[strtolower($message_id)] : $message_id;
        }

        function response($success = true, $code = false, $data = [])
        {
            $response = ['success' => $success ? true : false];

            if ($code) $response['code'] = strtoupper($code);
            if (!empty($data)) {
                if (is_object($data) || is_array($data))
                    $response['data'] = $data;
                else
                    $response['code'] = strtoupper($data);
            }

            return $response;
        }

        function success($code = false, $data = [])
        {
            return $this->response(true, $code, $data);
        }

        function error($code = false, $data = [])
        {
            return $this->response(false, $code, $data);
        }


        // token methods 
        function create_wrat_token()
        {
            return 'wrat.' . time() . '.' . bin2hex(random_bytes(16));
        }

        function getWRAT()
        {
            $token = false;
            $headers = $_SERVER["HTTP_AUTHORIZATION"] ?? false;
            if ($headers) {
                preg_match("/WRAT\s+[^\s]+/im", $headers, $match);
                if ($match && !empty($match) && count($match) > 0) {
                    $token = trim(str_replace('WRAT ', '', $match[0]));
                }
            }
            if (!$token) {
                $params = @file_get_contents('php://input');
                $token = json_decode($params)->wrat ?? false;
            }
            return $token;
        }

        function verifyWRAT()
        {
            if (is_user_logged_in()) {
                $user = $this->wrat_getUserFromObject(wp_get_current_user());
                unset($user->capabilities);

                return new WP_REST_Response($this->success('valid_rat', $user));
            }
            return new WP_REST_Response($this->success('invalid_rat'));
        }

        function deleteWRAT($token = false)
        {
            // delete existing token
            global $wpdb;
            if (!$token) $token = $this->getWRAT();
            if ($token) {
                $delete = $wpdb->query($wpdb->prepare("DELETE FROM $table_name WHERE token = '%s'", $token));
                return $delete;
            }
            return false;
        }

        function updateWRAT($user_id)
        {

            global $wpdb;
            $table_name = $wpdb->prefix . $this->table;

            $this->deleteWRAT($user_id);

            // create new token for the user 
            $token =  $this->create_wrat_token();
            $validity = apply_filters('wrat_validity', '1year');
            $wpdb->insert(
                $table_name,
                [
                    'user_id' => $user_id,
                    'token' => $token,
                    'validity' => date('Y-m-d H:i:s', strtotime('+' . $validity)),
                ]
            );

            return $token;
        }


        // user methods  

        function wrat_getUserFromObject($data)
        {

            if (!$data) return false;

            $output = new \StdClass();
            $output->id = (int) $data->data->ID;
            $output->first_name = get_user_meta($data->data->ID, 'first_name', true);
            $output->last_name = get_user_meta($data->data->ID, 'last_name', true);
            $output->email = $data->data->user_email;
            $output->role = $data->roles[0];

            $profile_picture = get_user_meta($data->data->ID, '_wrat_picture', true);
            $output->picture = $profile_picture;
            return $output;
        }

        function wrat_getUser()
        {
            if (is_user_logged_in()) {
                $user = wp_get_current_user();
                return $this->wrat_getUserFromObject($user);
            }
            return false;
        }

        function wrat_createUser($email = null, $password = null, $username = null)
        {

            if (!$email) return false;

            if (!$password) {
                $password = bin2hex(random_bytes(6));
            }

            # create unique username if not set 
            if (!$username) {
                $username = strtolower(explode('@', $email)[0]);
            }

            $user_id = false;
            while ($user_id = wp_create_user($username, $password, $email)) {
                if (!is_wp_error($user_id)) {
                    break;
                }
                $error_code = key($user_id->errors);
                if ($error_code == 'existing_user_login') {
                    $username .= rand(0, 9);
                    continue;
                }
                return false;
            }


            # after wat registration hook 
            do_action('wrat_after_registration', $user_id);
            return $user_id;
        }

        function wrat_loginUser($user)
        {
            # logged in 
            // if(!$user) return false;

            $token = $this->updateWRAT($user->data->ID);
            $user = $this->wrat_getUserFromObject($user);
            unset($user->capabilities);
            $user->token = $token;

            # after wat auth hook 
            do_action('wrat_after_login', $user->data->ID);
            return $user;
        }

        // automatic authenticate user 
        function wat_rest_init()
        {
            $token = $this->getWRAT();
            if ($token) {
                global $wpdb;
                $table_name = $wpdb->prefix . $this->table;
                $token = $wpdb->get_results($wpdb->prepare("SELECT user_id, validity FROM $table_name WHERE token = '$token' LIMIT 1"));

                if ($token && !empty($token)) {
                    $token = $token[0];
                    if (strtotime($token->validity) < time()) {
                        wp_send_json($this->error('token_expired'));
                    }
                    wp_set_current_user($token->user_id);
                }
            }

            // validate_wrat_endpoints
            $this->validate_wrat_endpoints();
        }

        function validate_wrat_endpoints()
        {

            $parsed_url = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
            $parsed_url = explode('?', $parsed_url)[0];
            $requested_url = trim(str_replace(home_url(), '', $parsed_url), '/');
            $wrat_default_endpoints = [
                '/wp-json/wat/v1/password/change',
                '/wp-json/wat/v1/refresh',
                '/wp-json/wat/v1/auth/test',
            ];

            $wrat_endpoints = apply_filters('wrat_endpoints',  $wrat_default_endpoints);

            // check url match 
            $checkAuth = false;
            foreach ($wrat_endpoints as $wrat_endpoint) {
                $wrat_endpoint = trim($wrat_endpoint, '/');
                $wrat_endpoint = str_replace(['*'], ['.+'], $wrat_endpoint);
                preg_match('~^' . $wrat_endpoint . '+$~', $requested_url, $match);
                if ($match[0]) {
                    $checkAuth = $match[0];
                    break;
                }
            }

            if ($checkAuth && !is_user_logged_in()) {
                $this->error('INVALID_WEB_AUTH_TOKEN');
            }
        }


        # Registering Endpoints
        function register_wrat_rests($server)
        {

            $routes = [

                // auth 
                ['auth',                    ['POST'],       'wrat_password_auth'],

                // socials 
                ['auth/facebook',           ['POST'],        'wrat_auth_facebook'],
                ['auth/google',             ['POST'],        'wrat_auth_google'],

                ['verify',                  ['GET'],        'verifyWRAT'],
                ['refresh',                 ['GET', 'POST'],        'refreshWRAT'],
                ['logout',                  ['GET', 'POST'],        'wrat_logout'],
                ['register',                ['POST'],       'wrat_register'],
                ['password/forgot',         ['POST'],        'wrat_sendPasswordResetEmail'],
                ['password/change',         ['POST'],        'wrat_changePassword'],


                // development 
                ['auth/test',               ['GET', 'POST'],        'auth_test'],

            ];

            foreach ($routes as $route) {
                register_rest_route('/wrat', $route[0], [
                    'methods'  => $route[1],
                    'callback' => [$this, $route[2]]
                ]);
            }
        }


        // endpoints 
        function wrat_password_auth($request)
        {
            # before wat login hook
            do_action('wrat_before_login');

            $user = $this->wrat_getUser();
            if ($user) {
                $user->token = $this->getWRAT();
                return new WP_REST_Response($this->success(false, $user));
            }

            # authenticate user 
            $email = $request['email'] ?? $request['username'] ?? null;
            $password = $request['password'] ?? null;

            $authenticated = wp_authenticate($email, $password);

            if ($authenticated->data == null) {

                $errors = array_map(function ($error) {
                    return $error;
                }, array_keys($authenticated->errors));

                return new WP_REST_Response($this->error(false, $errors[0]));
            }

            # logged in 
            $user = $this->wrat_loginUser($authenticated);

            # after wat auth hook 
            do_action('wrat_after_login', $user->id);

            return new WP_REST_Response($this->success(false, $user));
        }

        function refreshWRAT()
        {
        }

        function wrat_logout($request)
        {
            $id = get_current_user_id();
            if ($id)
                update_user_meta($id, '_wat_token', '');
            wp_logout();
            $this->success('LOGGED_OUT');
        }

        function wrat_register($request)
        {

            $register_allow = get_option('users_can_register');
            if (!$register_allow) {
                $this->error('not_allowed');
            }

            # before wat registration hook 
            do_action('wrat_before_registration', $request);

            $username = $request['username'] ?? null;
            $password = $request['password'] ?? null;
            $email = $request['email'] ?? null;

            if (!$email) {
                $this->error('invalid_email');
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->error('invalid_email');
            }

            $user_id = $this->wrat_createUser($email, $password, $username);
            if (!$user_id) {
                $this->error('existing_user_email');
            }

            # before wat registration hook 
            do_action('wrat_after_registration', $user_id);

            add_user_meta($user_id, '_wat_passwordless', false);

            update_user_meta($user_id, 'first_name', $request['first_name'] ?? '');
            update_user_meta($user_id, 'last_name', $request['last_name'] ?? '');

            $user = $this->wrat_loginUser(get_user_by('id', $user_id));
            $this->success($user);
        }

        function wrat_sendPasswordResetEmail($request)
        {
            $email = $request['email'] ?? false;
            $username = $request['username'] ?? false;
            if (!$email && !$username) {
                $this->error('empty_username');
            }

            $usisUserer = NULL;
            if ($email) {
                $isUser = get_user_by('email', $email);
            } else {
                $isUser = get_user_by('login', $username);
            }

            if (!$isUser) {
                $this->error('user_does_not_exist');
            }

            $user = new \WP_User(intval($isUser->ID));
            $reset_key = get_password_reset_key($user);
            $wc_emails = WC()->mailer()->get_emails();
            $sent = $wc_emails['WC_Email_Customer_Reset_Password']->trigger($user->user_login, $reset_key);

            $this->success('reset_email_sent');
        }

        function wrat_changePassword($request)
        {

            $user = $this->wrat_getUser();

            // check if the user is passwordless user 
            $passwordless = get_user_meta($user->id, '_wat_passwordless', true);

            if (!$passwordless) {
                $userIntance = get_user_by_email($user->email);

                $old_pass = $request['old'] ?? false;
                $force = $request['force'] ?? false;

                if (!$force && !$old_pass) {
                    $this->error('empty_old_password');
                }
                if (!wp_check_password($old_pass, $userIntance->data->user_pass, $user->id)) {
                    $this->error('incorrect_old_password');
                }
            }

            $new_pass = $request['password'] ?? false;
            if (!$new_pass) {
                $this->error('empty_password');
            }

            wp_set_password($new_pass, $user->id);

            // turn off passwordless mode 
            update_user_meta($user->id, '_wat_passwordless', false);

            $this->success('password_changed');
        }


        // api response 
        function wrat_curl($url = '', $data = [], $post = false)
        {
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_POST, $post ? 1 : 0);
            curl_setopt($curl, CURLOPT_URL, $url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

            if (!empty($data))
                curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

            $result = curl_exec($curl);
            $info = curl_getinfo($curl);

            curl_close($curl);
            return (object) [
                'type' => $info['content_type'],
                'code' => $info['http_code'],
                'response' => $result
            ];
        }

        // social login 

        // social facebook 
        function wrat_auth_facebook($request)
        {
            // required 
            $facebook_id = $request['facebook_id'] ?? false;
            $access_token = $request['access_token'] ?? false;

            if (!$facebook_id) $this->error('invalid_facebook_id');
            if (!$access_token) $this->error('invalid_access_token');

            // action 
            $action = $request['action'] ?? 'auth';


            $url = 'https://graph.facebook.com/' . $facebook_id . '?fields=id,first_name,last_name,email,picture&access_token=' . $access_token;

            $fb = $this->wrat_curl($url);
            $response = json_decode($fb->response);

            if (isset($response->error)) {
                $this->error($response->error->message);
            }

            // chech the email registered yet 
            $linkedUsers = get_users([
                'meta_key' => '_wrat_facebook',
                'meta_value' => $response->email
            ]);

            $linkedUser = $linkedUsers[0] ?? false;

            // response is ok 

            switch ($action) {
                case 'link':
                    // link account
                    if (is_user_logged_in()) {
                        if ($linkedUser) {
                            if ($linkedUser->ID == get_current_user_id()) {
                                $this->error('already_linked');
                            } else {
                                $this->error('linked_to_someone_else');
                            }
                        } else {
                            update_user_meta(get_current_user_id(), '_wrat_facebook', $response->email);
                            $this->success('facebook_linked');
                        }
                    } else {
                        $this->error('invalid_web_auth_token');
                    }
                    break;

                case 'unlink':
                    // unlink 
                    if (is_user_logged_in()) {
                        if ($linkedUser) {
                            if ($linkedUser->ID == get_current_user_id()) {

                                // check accessibility
                                $passwordless = get_user_meta(get_current_user_id(), '_wat_passwordless', true);
                                $googleConnected = get_user_meta(get_current_user_id(), '_wrat_google', true);
                                if ($passwordless && !$googleConnected) $this->error('You can not disconnect Facebook. Either connect Google or set Password first.');

                                update_user_meta(get_current_user_id(), '_wrat_facebook', '');
                                $this->success('facebook_unlinked');
                            } else {
                                $this->error('permission_denied');
                            }
                        } else {
                            $this->error('not_linked');
                        }
                    } else {
                        $this->error('invalid_web_auth_token');
                    }
                    break;

                default:
                    // auth account 


                    // if user registered 
                    if ($linkedUser) {

                        // login the user 
                        $data = $this->wrat_loginUser($linkedUser);
                        $this->success($data);
                    } else {
                        // user not registered 
                        // check the email registered 
                        $userByEmail = get_user_by_email($response->email);
                        // wp_send_json( $userByEmail );

                        if (is_a($userByEmail, '\WP_User')) {
                            // not connected yet 
                            $this->error('facebook_not_connected');
                        } else {

                            // register new account 
                            $user_id = $this->wrat_createUser($response->email);
                            add_user_meta($user_id, '_wat_passwordless', true);
                            update_user_meta($user_id, 'first_name', $response->first_name);
                            update_user_meta($user_id, 'last_name', $response->last_name);
                            update_user_meta($user_id, '_wrat_facebook', $response->email);
                            $picture = get_user_meta($user_id, '_wrat_picture', true);
                            if (empty($picture)) update_user_meta($user_id, '_wrat_picture', $response->picture->data->url);

                            $data = $this->wrat_loginUser(get_user_by('id', $user_id));
                            $this->response(true, $data, "SET_PASSWORD");
                        }
                    }
                    break;
            }
        }
        // social google 
        function wrat_auth_google($request)
        {
            // required fields 

            $access_token = $request['access_token'] ?? false;
            if (!$access_token) $this->error('access_token');

            // action 
            $action = $request['action'] ?? 'auth';

            $url = 'https://www.googleapis.com/oauth2/v3/userinfo?access_token=' . $access_token;

            $google = $this->wrat_curl($url);
            $response = json_decode($google->response);


            if (isset($response->error_description) && !empty($response->error_description)) {
                $this->error('invalid_access_token');
            }

            // response is ok 

            $linkedUsers = get_users([
                'meta_key' => '_wrat_google',
                'meta_value' => $response->email
            ]);
            $linkedUser = $linkedUsers[0] ?? false;

            switch ($action) {
                case 'link':
                    // link account
                    if (is_user_logged_in()) {
                        if ($linkedUser) {
                            if ($linkedUser->ID == get_current_user_id()) {
                                $this->error('already_linked');
                            } else {
                                $this->error('linked_to_someone_else');
                            }
                        } else {
                            update_user_meta(get_current_user_id(), '_wrat_google', $response->email);
                            $this->success('google_linked');
                        }
                    } else {
                        $this->error('invalid_web_auth_token');
                    }
                    break;

                case 'unlink':
                    // unlink account 
                    if (is_user_logged_in()) {
                        if ($linkedUser) {
                            if ($linkedUser->ID == get_current_user_id()) {
                                // check accessibility
                                $passwordless = get_user_meta(get_current_user_id(), '_wat_passwordless', true);
                                $facebookConnected = get_user_meta(get_current_user_id(), '_wrat_facebook', true);
                                if ($passwordless && !$facebookConnected) $this->error('You can not disconnect Google. Either connect Facebook or set Password first.');

                                update_user_meta(get_current_user_id(), '_wrat_google', '');
                                $this->success('google_unlinked');
                            } else {
                                $this->error('permission_denied');
                            }
                        } else {
                            $this->error('not_linked');
                        }
                    } else {
                        $this->error('invalid_web_auth_token');
                    }
                    break;

                default:
                    // auth account 
                    // chech the email registered yet 


                    // if user registered 
                    if ($linkedUser) {

                        // login the user 
                        $data = $this->wrat_loginUser($linkedUser);
                        $this->success($data);
                    } else {
                        // user not registered, so create one 
                        $userByEmail = get_user_by_email($response->email);

                        if (is_a($userByEmail, '\WP_User')) {
                            // not connected yet 
                            $this->error('not_linked');
                        } else {
                            // register new account 
                            $user_id = $this->wrat_createUser($response->email);
                            add_user_meta($user_id, '_wat_passwordless', true);
                            update_user_meta($user_id, 'first_name', $response->given_name);
                            update_user_meta($user_id, 'last_name', $response->family_name);
                            update_user_meta($user_id, '_wrat_google', $response->email);
                            $picture = get_user_meta($user_id, '_wrat_picture', true);
                            if (empty($picture)) update_user_meta($user_id, '_wrat_picture', $response->picture);

                            $data = $this->wrat_loginUser(get_user_by('id', $user_id));
                            $this->response(true, $data, "SET_PASSWORD");
                        }
                    }
                    break;
            }
        }

        // additional    
        function wrat_after_registration($user_id)
        {
            # update user meta
            add_user_meta($user_id, '_wrat_facebook', '');
            add_user_meta($user_id, '_wrat_google', '');
            add_user_meta($user_id, '_wrat_picture', '');
        }

        function after_wat_loaded()
        {
            # if jwt installed, whitelisting wat
            add_filter('jwt_auth_whitelist', function ($endpoints) {
                array_push($endpoints, $this->extended . '/wp-json/wat/*');
                return $endpoints;
            });
        }


        // development 
        function auth_test()
        {
            return new WP_REST_Response('Your ID is ' . get_current_user_id());
        }
    }


    // instance 
    $_wrat_plugin = new \WRAT\WRAT();
    $_wrat_plugin->init();
}
