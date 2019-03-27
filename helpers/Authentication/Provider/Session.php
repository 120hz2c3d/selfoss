<?php
/**
 * Created by PhpStorm.
 * User: cnagel
 * Date: 3/27/19
 * Time: 3:56 PM
 */

namespace helpers\Authentication\Provider;

use helpers\Authentication\ProviderInterface;


class Session implements ProviderInterface
{

    /**
     * @return bool
     */
    public function isLoggedIn()
    {
        return isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true;
    }

    /**
     * @return void
     */
    public function initialize()
    {
        $base_url = parse_url(\helpers\View::getBaseUrl());
        session_save_path (__DIR__ . '/../../../data/session');

        // session cookie will be valid for one month.
        $cookie_expire = 3600 * 24 * 30;
        $cookie_secure = $base_url['scheme'] === 'https';
        $cookie_httponly = true;
        $cookie_path = $base_url['path'];
        $cookie_domain = $base_url['host'];

        session_set_cookie_params(
            $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly
        );
        \F3::get('logger')->debug("set cookie on $cookie_domain$cookie_path expiring in $cookie_expire seconds");

        session_name();
        if (session_id() === '') {
            session_start();
        }

    }

    /**
     * @return void
     */
    public function login()
    {
        $_SESSION['loggedin'] = true;
    }

    /**
     * @return string|null
     */
    public function getPayload()
    {
        return null;
    }

    /**
     * @return void
     */
    public function logout()
    {
        $_SESSION['loggedin'] = false;
        session_destroy();
    }
}
