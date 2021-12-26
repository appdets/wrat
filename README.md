# WRAT
WRAT in the abbreviation of WordPress REST Auth Token. In simple words, WRAT is an oAuth2 implementation SDK for WordPress REST API. 

# <a name="#install"></a> Install

## Using composer
- [x] Open your bash/terminal and run the command
```bash
composer require wrat
```
 
## Manual installation
- [x] [Download as zip](https://github.com/imjafran/wrat/archive/refs/heads/master.zip)
- [x] Extract into your project directory
- [x] Require **wrat** file
 

## Initializing WRAT
```php
<?php
// require using composer
require __DIR__ . "/vendor/autoload.php";
// or require the file
require_once __DIR__ . "/path/to/wrat.php";

// Initializing WRAT
WRAT::init();
// WRAT initalized
```

# <a name="#usage"></a> Usages
WRAT has two endpoints to handle authentication stuffs. 
- [Auth](#auth)
- [Verify](#verify)

In Next
- [Communicating with server](#communicate)


## <a name="#auth"></a> Auth
Authenticates email/username and password pair from request payload and returns access token for further usages. 

### Endpoint
```
/wp-json/wrat/auth
```
### Method
*POST* only
### Request payload
```json
{
    "email" : "user@email.com",
    // "username" : "myusername", // alternative of email
    "password" : "12345", // application password can be used
    "refresh" : false // default : false
}
```

### Response body
#### Success
```json
{
    "success": true,
    "user": {
        "id": 21,
        "first_name": "Test",
        "last_name": "User",
        "email": "test@gmail.com",
        "role": "customer",
        "token": "ACCESS_TOKEN_HERE"
    }
}
```

#### Failed
```json
{
    "success": false,
    "code": "ERROR_CODE_HERE"
}
```

### List of Error Codes
- **invalid_wrat** - The provided token is incorrect.
- **invalid_email** - The email is either empty or invalid or incorrect.
- **incorrect_username** - The username is either empty or wrong, works if no email parameter found.
- **incorrect_password** - The provided password is incorrect.

### Refresh
Refreshing token will create new token pair forcefully, otherwise returns existing token if found and created new only no token found. 

By default `{refresh : false}`


## Verify
Verifies requested token, if its working

#### Endpoint
```
/wp-json/wrat/verify
```

#### Request payload
```json
{
    "wrat" : "TOKEN_HERE"
}
```

#### Response body

Same as before.  [*See auth section*](#auth)

NOTE: Here, only JSON payload has been showns as example, but all available methods of server requests work with WRAT. 

<br>
 

## Communicating with server
From you REST client, you can pass WRAT token as `bearer token`, `request payload`, `query parameter` and obviously as `json` 

### Bearer Token 
```
curl https://your-wordpress-site.com/wp-json
   -H "Accept: application/json"
   -H "Authorization: Bearer {TOKEN_HERE}"
```

alternatively,
```
curl https://your-wordpress-site.com/wp-json
   -H "Accept: application/json"
   -H "Authorization: WRAT {TOKEN_HERE}"
```

### URL Query Parameter
```
https://your-wordpress-site.com/wp-json/your/route/?wrat=TOKEN_HERE
```

### Request Payload
```json
{
    "some"  : "data",
    "wrat   : "TOKEN_HERE"
}
```

A valid token will make sure that the server knowns your identity in REST operation. Simply, this will occur `is_user_logged_in() // true` over whole REST API of that website.  

<br>

# Extending

- [Action hooks](#action_hooks)
- [Filter hooks](#filter_hooks)

## Action hooks

#### `wrat_before_auth`
Executed before comparing email/email and password pair. 

Example
```php
function wrat_before_auth_callback(){
    /**
     * do whatever you want 
     **/
}
add_action('wrat_before_auth', 'wrat_before_auth_callback', 0, 12);
```


#### `wrat_after_auth`
Executed after authenticated successfully. 

Example
```php
function wrat_after_auth_callback( $user_id ){
    /**
     * @user_id Integer 
     * */
}
add_action('wrat_after_auth', 'wrat_after_auth_callback', 1, 12);
```


#### `wrat_auth_failed`
Executed after authentication failed.

Example
```php
function wrat_auth_failed_callback( $email, $username, $errors ){
    /**
     * @email String
     * @username String
     * @errors Array
     * */
}
add_action('wrat_auth_failed', 'wrat_auth_failed_callback', 3, 12);
```



## Filter hooks

#### `wrat_user_data`
Userdata object returns after authentication


Example
```php
function wrat_user_data_callback( $data ){
    /**
     * @data Object 
     * */
    return $data;
}
add_filter('wrat_user_data', 'wrat_user_data_callback');
```


#### `wrat_blacklist_endpoints`

Example
```php
/**
 * @enabled Boolean
 * 
 * Default : true 
 * */
function wrat_blacklist_endpoints_callback( $enabled ){

    return $enabled;

}

add_filter('wrat_blacklist_endpoints',  'wrat_blacklist_endpoints_callback');
```

#### `wrat_endpoints`
The endpoints you define will act exactly opposite of rest of the endpoints.


Example
```php
/**
 * @endpoints Array
 * 
 * Default : [] 
 * */

function wrat_endpoints_callback( $endpoints ){
    $endpoints[] = 'some/endpoints/*';
    $endpoints[] = 'another/endpoint';

    return $endpoints; 
}

add_filter('wrat_endpoints',  'wrat_endpoints_callback');
```

#### `wrat_endpoint_prefix`
#### `wrat_cors`
