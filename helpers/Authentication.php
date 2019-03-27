<?php

namespace helpers;

use helpers\Authentication\ProviderInterface;

/**
 * Helper class for authenticate user
 *
 * @copyright  Copyright (c) Tobias Zeising (http://www.aditu.de)
 * @license    GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)
 * @author     Tobias Zeising <tobias.zeising@aditu.de>
 */
class Authentication {
    const AUTH_TYPE_COOKIE = 'auth_cookie';
    const AUTH_TYPE_JWT = 'auth_jwt';

    /** @var bool loggedin */
    private $loggedin = false;

    /** @var string authType*/
    private $authType;

    /** @var ProviderInterface authProvider */
    private $authProvider;

    /**
     * start session and check login
     * @param string $authType
     */
    public function __construct($authType = self::AUTH_TYPE_COOKIE) {
        if ($this->enabled() === false) {
            return;
        }

        $this->authType = $authType;

        $authProvider = $this->getAuthProvider();
        $authProvider->initialize();

        $this->setLoggedInByAuthProvider($authProvider);

        if ($this->isLoggedin() === false) {
            $this->tryToLoginByRequest();
        }

    }

    /**
     * @return ProviderInterface
     */
    private function getAuthProvider() {
        if ($this->authProvider === null) {
            $this->authProvider = $this->getProviderByAuthType($this->authType);
        }

        return $this->authProvider;
    }

    /**
     * @param string $authType
     * @return Authentication\ProviderInterface
     */
    private function getProviderByAuthType($authType)
    {
        if ($authType === self::AUTH_TYPE_COOKIE) {
            return new Authentication\Provider\Session();
        }

        if ($authType === self::AUTH_TYPE_JWT) {
            return new Authentication\Provider\JsonWebToken();
        }

        \F3::get('logger')->debug('Invalid auth type given - use session as fallback');
        return new Authentication\Provider\Session();
    }

    /**
     * @param ProviderInterface $authProvider
     */
    private function setLoggedInByAuthProvider(ProviderInterface $authProvider) {
        $this->loggedin = $authProvider->isLoggedIn();

        if ($this->loggedin) {
            \F3::get('logger')->debug('logged in using valid session');
        } else {
            \F3::get('logger')->debug('session does not contain valid auth');
        }
    }

    /**
     * login enabled
     *
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    public function enabled() {
        return strlen(trim(\F3::get('username'))) != 0 && strlen(trim(\F3::get('password'))) != 0;
    }

    /**
     * login user
     *
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    public function login($username, $password) {
        if ($this->enabled()) {
            if (
                $username === \F3::get('username') && hash('sha512', \F3::get('salt') . $password) === \F3::get('password')
            ) {
                $this->loggedin = true;

                $this->getAuthProvider()->login();

                \F3::get('logger')->debug('logged in with supplied username and password');

                return true;
            } else {
                \F3::get('logger')->debug('failed to log in with supplied username and password');

                return false;
            }
        }

        return true;
    }

    /**
     * isloggedin
     *
     * @return bool
     */
    public function isLoggedin() {
        if ($this->enabled() === false) {
            return true;
        }

        return $this->loggedin;
    }

    /**
     * showPrivateTags
     *
     * @return bool
     */
    public function showPrivateTags() {
        return $this->isLoggedin();
    }

    /**
     * logout
     *
     * @return void
     */
    public function logout() {
        $this->loggedin = false;
        $this->getAuthProvider()->logout();

        \F3::get('logger')->debug('logged out');
    }

    /**
     * tryToLoginByRequest
     */
    private function tryToLoginByRequest()
    {
        if (isset($_REQUEST['username'])
            && isset($_REQUEST['password'])) {
            $this->login($_REQUEST['username'], $_REQUEST['password']);
        }
    }

    /**
     * @return string|null
     */
    public function getPayload()
    {
        return $this->getAuthProvider()->getPayload();
    }
}
