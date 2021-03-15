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
        public $extended = '/';
        private $table = 'wrat_tokens';

        function __construct()
        {
            $this->extended = str_replace('/index.php', '', $_SERVER['PHP_SELF']);
        }

        # Register Hooks 
        function init()
        {
            # installation hooks
            register_activation_hook(__FILE__,                  [$this, 'wrat_activate_plugin']);

            # custom construct method       
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
                token varchar(250) DEFAULT NULL,
                created datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
                validity datetime DEFAULT NULL,
                PRIMARY KEY (id)
            ) $charset_collate;";

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);
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
                preg_match("/WRAT.[^\s]+/im", $headers, $match);
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
                return new WP_REST_Response($this->success('valid_wrat', $user));
            }
            return new WP_REST_Response($this->error('invalid_wrat'));
        }

        function deleteWRAT($token = false)
        {
            if (!$token) $token = $this->getWRAT();
            if ($token) {
                global $wpdb;
                $table_name = $wpdb->prefix . $this->table;
                $delete = $wpdb->query("DELETE FROM $table_name WHERE `token` = '{$token}';");
                return $delete;
            }
            return false;
        }

        function updateWRAT($user_id = false)
        {
            if (!$user_id) $user_id = get_current_user_id();
            if (!$user_id) return false;

            global $wpdb;
            $table_name = $wpdb->prefix . $this->table;

            $this->deleteWRAT();

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
            $output->picture = get_user_meta($data->data->ID, '_wrat_picture', true);
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
            $token = $this->updateWRAT($user->data->ID);
            $user = $this->wrat_getUserFromObject($user);
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
                $tokenFromDB = $wpdb->get_results($wpdb->prepare("SELECT user_id, validity FROM $table_name WHERE token = '$token' LIMIT 1"));

                if ($tokenFromDB && !empty($tokenFromDB)) {
                    $tokenFromDB = $tokenFromDB[0];
                    if (strtotime($tokenFromDB->validity) > time()) {
                        wp_set_current_user($tokenFromDB->user_id);
                    } else {
                        $this->deleteWRAT($token);
                    }
                }
            }

            // validate_wrat_endpoints
            if ($this->isWRATRestrictedRoute()) wp_send_json($this->error('invalid_wrat'));
        }

        function isWRATRestrictedRoute()
        {

            $parsed_url = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
            $parsed_url = explode('?', $parsed_url)[0];
            $requested_url = trim(str_replace(home_url(), '', $parsed_url), '/');
            $wrat_default_endpoints = [
                '/wp-json/wrat/refresh',
                '/wp-json/wrat/password/change'
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

            return $checkAuth && !is_user_logged_in();
        }


        # Registering Endpoints
        function register_wrat_rests($server)
        {

            $routes = [

                ['register',                ['POST'],               'wrat_register'],

                // auth 
                ['auth',                    ['POST'],               'wrat_password_auth'],

                // socials 
                ['auth/facebook',           ['POST'],               'wrat_auth_facebook'],
                ['auth/google',             ['POST'],               'wrat_auth_google'],

                ['verify',                  ['GET', 'POST'],        'verifyWRAT'],
                ['refresh',                 ['GET', 'POST'],        'refreshWRAT'],
                ['logout',                  ['GET', 'POST'],        'wrat_logout'],
                ['password/forgot',         ['POST'],               'wrat_sendPasswordResetEmail'],
                ['password/change',         ['POST'],               'wrat_changePassword'],

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
            $user = $this->wrat_getUser();
            if ($user) {
                $user->token = $this->updateWRAT();
                return new WP_REST_Response($this->success(false, $user));
            }
            return new WP_REST_Response($this->error('invalid_wrat'));
        }

        function wrat_logout()
        {
            $this->deleteWRAT();
            wp_logout();
            return new WP_REST_Response($this->success('LOGGED_OUT'));
        }

        function wrat_register($request)
        {

            $register_allow = get_option('users_can_register');
            if (!$register_allow) return new WP_REST_Response($this->error('not_allowed'));

            # before wat registration hook 
            do_action('wrat_before_registration', $request);

            $username = $request['username'] ?? null;
            $password = $request['password'] ?? null;
            $email = $request['email'] ?? null;

            if (!$email || !is_email($email)) {
                return new WP_REST_Response($this->error('invalid_email'));
            }

            $user_id = $this->wrat_createUser($email, $password, $username);
            if (!$user_id) {
                return new WP_REST_Response($this->error('existing_user_email'));
            }

            # before wat registration hook 
            do_action('wrat_after_registration', $user_id, $request);

            add_user_meta($user_id, '_wrat_passwordless', false);

            update_user_meta($user_id, 'first_name', $request['first_name'] ?? '');
            update_user_meta($user_id, 'last_name', $request['last_name'] ?? '');

            $user = $this->wrat_loginUser(get_user_by('id', $user_id));
            return new WP_REST_Response($this->success('registration_success', $user));
        }

        function wrat_sendPasswordResetEmail($request)
        {
            $email = $request['email'] ?? false;
            $username = $request['username'] ?? false;
            if (!$email && !$username) return new WP_REST_Response($this->error('empty_username'));

            $isUser = NULL;
            if ($email && is_email($email)) {
                $isUser = get_user_by('email', $email);
            } else if ($username) {
                $isUser = get_user_by('login', $username);
            } else {
                // do nothing 
            }

            if (!$isUser) return new WP_REST_Response($this->error('user_does_not_exist'));

            $user = new \WP_User(intval($isUser->ID));
            $reset_key = get_password_reset_key($user);
            $wc_emails = WC()->mailer()->get_emails();
            $sent = $wc_emails['WC_Email_Customer_Reset_Password']->trigger($user->user_login, $reset_key);

            return new WP_REST_Response($this->success('reset_email_sent'));
        }

        function wrat_changePassword($request)
        {

            $user = $this->wrat_getUser();

            // check if the user is passwordless user 
            $passwordless = get_user_meta($user->id, '_wrat_passwordless', true);

            if (!$passwordless) {
                $userIntance = get_user_by_email($user->email);

                $old_pass = $request['old'] ?? false;
                $force = $request['force'] ?? false;

                if (!$force && !$old_pass) return new WP_REST_Response($this->error('empty_old_password'));
                if (!wp_check_password($old_pass, $userIntance->data->user_pass, $user->id)) return new WP_REST_Response($this->error('incorrect_old_password'));
            }

            $new_pass = $request['password'] ?? false;
            if (!$new_pass) return new WP_REST_Response($this->error('empty_password'));

            wp_set_password($new_pass, $user->id);

            // turn off passwordless mode 
            update_user_meta($user->id, '_wrat_passwordless', false);

            return new WP_REST_Response($this->success('password_changed'));
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

            if (!$facebook_id) return new WP_REST_Response($this->error('invalid_facebook_id'));
            if (!$access_token) return new WP_REST_Response($this->error('invalid_access_token'));

            // action 
            $action = $request['action'] ?? 'auth';


            $url = 'https://graph.facebook.com/' . $facebook_id . '?fields=id,first_name,last_name,email,picture&access_token=' . $access_token;

            $fb = $this->wrat_curl($url);
            $response = json_decode($fb->response);

            if (isset($response->error)) {
                return new WP_REST_Response($this->error($response->error->message));
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
                                return new WP_REST_Response($this->error('already_linked'));
                            } else {
                                return new WP_REST_Response($this->error('linked_to_someone_else'));
                            }
                        } else {
                            update_user_meta(get_current_user_id(), '_wrat_facebook', $response->email);
                            return new WP_REST_Response($this->success('facebook_linked'));
                        }
                    } else {
                        return new WP_REST_Response($this->error('invalid_wrat'));
                    }
                    break;

                case 'unlink':
                    // unlink 
                    if (is_user_logged_in()) {
                        if ($linkedUser) {
                            if ($linkedUser->ID == get_current_user_id()) {

                                // check accessibility
                                $passwordless = get_user_meta(get_current_user_id(), '_wrat_passwordless', true);
                                $googleConnected = get_user_meta(get_current_user_id(), '_wrat_google', true);
                                if ($passwordless && !$googleConnected) $this->error('You can not disconnect Facebook. Either connect Google or set Password first.');

                                update_user_meta(get_current_user_id(), '_wrat_facebook', '');
                                return new WP_REST_Response($this->success('facebook_unlinked'));
                            } else {
                                return new WP_REST_Response($this->error('permission_denied'));
                            }
                        } else {
                            return new WP_REST_Response($this->error('not_linked'));
                        }
                    } else {
                        return new WP_REST_Response($this->error('invalid_wrat'));
                    }
                    break;

                default:
                    // auth account 


                    // if user registered 
                    if ($linkedUser) {

                        // login the user 
                        $data = $this->wrat_loginUser($linkedUser);
                        return new WP_REST_Response($this->success($data));
                    } else {
                        // user not registered 
                        // check the email registered 
                        $userByEmail = get_user_by_email($response->email);
                        // wp_send_json( $userByEmail );

                        if (is_a($userByEmail, '\WP_User')) {
                            // not connected yet 
                            return new WP_REST_Response($this->error('facebook_not_connected'));
                        } else {

                            // register new account 
                            $user_id = $this->wrat_createUser($response->email);
                            add_user_meta($user_id, '_wrat_passwordless', true);
                            update_user_meta($user_id, 'first_name', $response->first_name);
                            update_user_meta($user_id, 'last_name', $response->last_name);
                            update_user_meta($user_id, '_wrat_facebook', $response->email);
                            $picture = get_user_meta($user_id, '_wrat_picture', true);
                            if (empty($picture)) update_user_meta($user_id, '_wrat_picture', $response->picture->data->url);

                            $data = $this->wrat_loginUser(get_user_by('id', $user_id));
                            return new WP_REST_Response($this->response(true, $data, "SET_PASSWORD"));
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
                return new WP_REST_Response($this->error('invalid_access_token'));
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
                                return new WP_REST_Response($this->error('already_linked'));
                            } else {
                                return new WP_REST_Response($this->error('linked_to_someone_else'));
                            }
                        } else {
                            update_user_meta(get_current_user_id(), '_wrat_google', $response->email);
                            return new WP_REST_Response($this->success('google_linked'));
                        }
                    } else {
                        return new WP_REST_Response($this->error('invalid_wrat'));
                    }
                    break;

                case 'unlink':
                    // unlink account 
                    if (is_user_logged_in()) {
                        if ($linkedUser) {
                            if ($linkedUser->ID == get_current_user_id()) {
                                // check accessibility
                                $passwordless = get_user_meta(get_current_user_id(), '_wrat_passwordless', true);
                                $facebookConnected = get_user_meta(get_current_user_id(), '_wrat_facebook', true);
                                if ($passwordless && !$facebookConnected) $this->error('You can not disconnect Google. Either connect Facebook or set Password first.');

                                update_user_meta(get_current_user_id(), '_wrat_google', '');
                                return new WP_REST_Response($this->success('google_unlinked'));
                            } else {
                                return new WP_REST_Response($this->error('permission_denied'));
                            }
                        } else {
                            return new WP_REST_Response($this->error('not_linked'));
                        }
                    } else {
                        return new WP_REST_Response($this->error('invalid_wrat'));
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
                            return new WP_REST_Response($this->error('not_linked'));
                        } else {
                            // register new account 
                            $user_id = $this->wrat_createUser($response->email);
                            add_user_meta($user_id, '_wrat_passwordless', true);
                            update_user_meta($user_id, 'first_name', $response->given_name);
                            update_user_meta($user_id, 'last_name', $response->family_name);
                            update_user_meta($user_id, '_wrat_google', $response->email);
                            $picture = get_user_meta($user_id, '_wrat_picture', true);
                            if (empty($picture)) update_user_meta($user_id, '_wrat_picture', $response->picture);

                            $data = $this->wrat_loginUser(get_user_by('id', $user_id));
                            return new WP_REST_Response($this->response(true, $data, "SET_PASSWORD"));
                        }
                    }
                    break;
            }
        }

        // additional    
        function wrat_after_registration($user_id, $request = null)
        {
            # update user meta
            add_user_meta($user_id, '_wrat_facebook', '');
            add_user_meta($user_id, '_wrat_google', '');
            add_user_meta($user_id, '_wrat_picture', '');
        }
    }


    // instance 
    $_wrat_plugin = new \WRAT\WRAT();
    $_wrat_plugin->init();
}
