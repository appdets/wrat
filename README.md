**W**ordPress **R**EST **A**uth **T**oken.

Lightweight SDK to implement oAuth2 authentication system for WordPress REST API.


<br>


*Table of contents*
- [Features](#features)
- [Install](#install)
- [Usages](#usages)
  - [Access token](#access-token)
  - [Verify](#verify)
  - [Authentication](#authentication)
  - [Refresh token](#refresh-token)
- [List of Error Codes](#list-of-error-codes)
- [Customization](#customization)
  - [Action hooks](#action-hooks)
  - [Filter hooks](#filter-hooks)
  - [Functions](#functions)
- [Contribution](#contribution)


<br>

# Features
- [x] Easy to learn, easy to use
- [x] Opensource
- [x] Forever free
- [x] Lightweight (Less than 10kb)
- [x] No dependency
- [x] Supports [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [x] Full customizable

<br>

# Install

[**Using composer**](https://packagist.org/packages/wrat/wrat)

Open your bash/terminal and run the command
```bash
composer require wrat/wrat
```

[**Clone from Git**](https://github.com/imjafran/wrat/)

Open you terminal in targeted directory and run the commans
```bash
git clone https://github.com/imjafran/wrat.git ./
```
 
 
**Manual installation**

- [x] [Download as zip](https://github.com/imjafran/wrat/archive/refs/heads/master.zip)
- [x] Extract into your project directory
- [x] Require `wrat.php` file
 

**Initializing WRAT**
```php
<?php
# require using composer
require __DIR__ . "/vendor/autoload.php";

# or require directly
require_once __DIR__ . "/path/to/wrat.php";

# Initializing WRAT
WRAT::init();
```

<br>


# Usages
WRAT has two endpoints to handle authentication stuffs. Once you install WRAT, these endpoints will be registered automatically.

- [Access token](#access_token)
- [Verify](#verify)
- [Authentication](#authentication)
- [Refresh token](#refresh-token)


## Access token
Authenticates email/username and password pair from request payload and returns access token for further usages. 

**Endpoint**

```
/wp-json/wrat/token
``` 

**Method** : `POST`

Request payload

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

**Response body**

Success

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

Failed

```json
{
    "success": false,
    "code": "ERROR_CODE_HERE"
}
```

- See [List of error codes](#list-of-error-codes) for error references
- See [Refresh Token](#refresh-token) to refresh the token

<br> 

## Verify
Verifies requested token, if its working

Endpoint

```
/wp-json/wrat/verify
```
**Method** : `POST`

Request payload
```json
{
    "wrat" : "TOKEN_HERE"
}
```

**Response body**

Same as before.  [*See auth section*](#auth-response)

NOTE: Here, only JSON payload has been showns as example, but all available methods of server requests work with WRAT. 

<br>

___

<br>


## Authentication
From you REST client, you can pass WRAT token as `bearer token`, `request payload`, `query parameter` and obviously as `json` to authenticate current user. 


**Bearer token**

```
curl https://your-wordpress-site.com/wp-json
   -H "Accept: application/json"
   -H "Authorization: Bearer {TOKEN_HERE}"
```

alternatively, custom authorization
```
curl https://your-wordpress-site.com/wp-json
   -H "Accept: application/json"
   -H "Authorization: WRAT {TOKEN_HERE}"
```

**URL query parameter**

```
https://your-wordpress-site.com/wp-json/your/route/?wrat=TOKEN_HERE
```

**Request payload**

```json
{
    "some"  : "data",
    "wrat"   : "TOKEN_HERE"
}
```

A valid token will make sure that the server knowns your identity in REST operation. Simply, this will occur `is_user_logged_in() // true` over whole REST API of that website.  



<br> 

## Refresh token
Refreshing token will create new token pair forcefully, otherwise returns existing token if found and created new only no token found. 

```json
{
    "email" : "user@email.com",
    "password" : "12345",
    "refresh" : true
}
```

<br>


# List of Error Codes
- [x] **invalid_wrat** - The provided token is incorrect.
- [x] **invalid_email** - The email is either empty or invalid or incorrect.
- [x] **incorrect_username** - The username is either empty or wrong, works if no email parameter found.
- [x] **incorrect_password** - The provided password is incorrect.
___ 

<br>

# Customization

- [Action hooks](#action_hooks)
- [Filter hooks](#filter_hooks)
- [Functions](#functions)

## Action hooks

**`wrat_before_auth`**

Executed before comparing email/email and password pair. 

Example
```php
function wrat_before_auth_callback(){
    /**
     * do whatever you want 
     **/
}
add_action('wrat_before_auth', 'wrat_before_auth_callback', 12, 0);
```


**`wrat_after_auth`**

Executed after authenticated successfully. 

Example
```php
function wrat_after_auth_callback( $user_id ){
    /**
     * @user_id Integer 
     * */
}
add_action('wrat_after_auth', 'wrat_after_auth_callback', 12, 1);
```


**`wrat_auth_failed`**

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
add_action('wrat_auth_failed', 'wrat_auth_failed_callback', 12, 3);
```



## Filter hooks

**`wrat_cors`**

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


**`wrat_endpoints`**

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



**`wrat_blacklist_endpoints`**

There are two modes. 

- `Whitelisting` 
- `Blacklisting`

If *wrat_blacklist_endpoints* is `true`, only wrat filtered endpoints will require authentication, rest of the endpoints will be open. 

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

**`wrat_endpoint_prefix`**

Add the extended url prefix if your WordPress site in installed in a sub directory. 

If your site is like this 
`yoursite.com/staging/wp-json/wrat/token`

`staging` is your endpoint prefix. Add this as `wrat_endpoint_prefix`


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


**`wrat_user_data`**

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

## Functions

**`wrat_get_token`**

Returns user's access token from user id

Example

```php
$token = wrat_get_token(int $user_id);

# returns string token
```


**`wrat_get_user`**

Returns user data including access token from user id

Example

```php
$user = wrat_get_user(int $user_id);
# or 
$user = wrat_get_user(WP_User $user);

# returns object data
```


# Contribution

**Publisher** [Jafran Hasan](https://www.facebook.com/IamJafran)

**Contributors**
- [x] [You should be here](#)


Wanna see your name in the list?
[Git Repository](https://github.com/imjafran/wrat)


Pulling requests are welcome but please open a ticket before pushing to discus on what you would like to extend. 