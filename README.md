# WRAT 3.0

Lightweight superfast SDK for implementing oAuth2 authentication system in WordPress REST API. `(Less than 10 kb)`. 

**WRAT** in the abbreviation of **W**ordPress **R**EST **A**uth **T**oken. In simple words, WRAT is an oAuth2 implementation **SDK** for WordPress REST API. 


<br>


*Table of contents*
- [WRAT 3.0](#wrat-30)
- [Features](#features)
- [Install](#install)
    - [Using composer](#using-composer)
    - [Manual installation](#manual-installation)
    - [Initializing WRAT](#initializing-wrat)
- [Usages](#usages)
  - [Auth](#auth)
    - [Endpoint](#endpoint)
    - [Method](#method)
    - [Request payload](#request-payload)
    - [Response body](#response-body)
      - [Success](#success)
      - [Failed](#failed)
    - [List of Error Codes](#list-of-error-codes)
    - [Refresh token](#refresh-token)
  - [Verify](#verify)
      - [Endpoint](#endpoint-1)
      - [Request payload](#request-payload-1)
      - [Response body](#response-body-1)
  - [Communicating with server](#communicating-with-server)
    - [Bearer Token](#bearer-token)
    - [URL Query Parameter](#url-query-parameter)
      - [Request Payload](#request-payload-2)
- [Extending](#extending)
  - [Action hooks](#action-hooks)
      - [`wrat_before_auth`](#wrat_before_auth)
      - [`wrat_after_auth`](#wrat_after_auth)
      - [`wrat_auth_failed`](#wrat_auth_failed)
  - [Filter hooks](#filter-hooks)
      - [`wrat_cors`](#wrat_cors)
      - [`wrat_endpoints`](#wrat_endpoints)
      - [`wrat_blacklist_endpoints`](#wrat_blacklist_endpoints)
      - [`wrat_endpoint_prefix`](#wrat_endpoint_prefix)
      - [`wrat_user_data`](#wrat_user_data)
- [Contribution](#contribution)


<br>

# Features
- [x] Opensource
- [x] Forever free
- [x] Lightweight (3kb)
- [x] Superfast, no overloading
- [x] No dependency
- [x] Supports [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [x] Works with Bearer token
- [x] Secure and privacy friendly
- [x] Endpoint filtering, whitelisting, blacklisting
- [x] Full customizable

<br>

# Install

### Using composer
- [x] Open your bash/terminal and run the command
```bash
composer require wrat
```
 
### Manual installation
- [x] [Download as zip](https://github.com/imjafran/wrat/releases/tag/v3.0)
- [x] Extract into your project directory
- [x] Require `wrat.php` file
 

### Initializing WRAT
```php
<?php
// require using composer
require __DIR__ . "/vendor/autoload.php";
// or require directly
require_once __DIR__ . "/path/to/wrat.php";

// Initializing WRAT
WRAT::init();
```

<br>


# Usages
WRAT has two endpoints to handle authentication stuffs. 
- [Auth](#auth)
- [Verify](#verify)

In Next
- [Communicating with server](#communicate)


## Auth
Authenticates email/username and password pair from request payload and returns access token for further usages. 

### Endpoint
```
/wp-json/wrat/auth
```
### Method
*POST* only
### Request payload

Using email-password pair
```json
{
    "email" : "user@email.com",
    "password" : "12345",
}
```
or using username instead
```json
{
    "username" : "your-username",
    "password" : "12345",
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


<br> 

### Refresh token
Refreshing token will create new token pair forcefully, otherwise returns existing token if found and created new only no token found. 

```json
{
    "email" : "user@email.com",
    "password" : "12345",
    "refresh" : true
}
```

<br> 

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

Same as before.  [*See auth section*](#auth_response)

NOTE: Here, only JSON payload has been showns as example, but all available methods of server requests work with WRAT. 

<br>

___

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

#### Request Payload
```json
{
    "some"  : "data",
    "wrat"   : "TOKEN_HERE"
}
```

A valid token will make sure that the server knowns your identity in REST operation. Simply, this will occur `is_user_logged_in() // true` over whole REST API of that website.  

<br>

___ 

<br>
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
#### `wrat_cors`

Enabling CORS will let In-Browser-JavaScript work with your REST API. By default, it's enabled to all request origins. You may customize the CORS urls. 

Example
```php
/**
 * @urls String
 * 
 * Default : "*"
 * */

function wrat_cors_callback( $urls = '*' ){
     
    return $urls; 

}

add_filter('wrat_cors',  'wrat_cors_callback');
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

function wrat_endpoints_callback( $endpoints = [] ){
    $endpoints[] = 'some/endpoints/*';
    $endpoints[] = 'another/endpoint';

    return $endpoints; 
}

add_filter('wrat_endpoints',  'wrat_endpoints_callback');
```



#### `wrat_blacklist_endpoints`

There are two modes. 
`Whitelisting` and `Blacklisting`

If `wrat_blacklist_endpoints` is `true`, only wrat filtered endpoints will require authentication, rest of the endpoints will be be excluded from authentication. 

Example
```php
/**
 * @enabled Boolean
 * 
 * Default : true 
 * */
function wrat_blacklist_endpoints_callback( $enabled = true ){

    return $enabled;

}

add_filter('wrat_blacklist_endpoints',  'wrat_blacklist_endpoints_callback');
```


#### `wrat_endpoint_prefix`

Add the extended url prefix if your WordPress site in installed in a sub directory. 

If your site is like this 
`yoursite.com/staging/wp-json/wrat/auth`

`staging` is your endpoint prefix. Add this as wrat_endpoint_prefix


Example
```php
/**
 * @endpoints String
 * 
 * Default : ""
 * */

function wrat_endpoint_prefix_callback( $prefix = '' ){ 

    return $endpoints; 

}

add_filter('wrat_endpoint_prefix',  'wrat_endpoint_prefix_callback');
```


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


# Contribution
Publisher [Jafran Hasan](https://www.facebook.com/IamJafran)

Pulling requests are welcome but please open a ticket before pushing to discus on what you would like to extend. 