<?php
/**
 * Created by PhpStorm.
 * User: cnagel
 * Date: 3/27/19
 * Time: 3:56 PM
 */

namespace helpers\Authentication\Provider;


use helpers\Authentication\ProviderInterface;
use Firebase\JWT\JWT;

class JsonWebToken implements ProviderInterface
{
    /**
     * currently no RSA supported cause of missing config
     *
     * @var string
     */
    const JWT_ALGORITHM = 'HS512';

    /** @var bool */
    private $loggedIn;

    /**
     * @return bool
     */
    public function isLoggedIn()
    {
        return $this->loggedIn;
    }

    /**
     * @return void
     */
    public function initialize()
    {
        $auth = true;
        $payload = $this->getDecodedPayload();

        if ($payload !== null && $auth === true) {
            $this->login();
        }
        else {
            $this->logout();
        }
    }

    /**
     * @return void
     */
    public function logout()
    {
        $this->loggedIn = false;
    }

    /**
     * @return void
     */
    public function login()
    {
        $this->loggedIn = true;
    }

    /**
     * @return string|null
     */
    public function getPayload()
    {
        if ($this->isLoggedIn()) {
            return JWT::encode($this->getJwtPayload(), $this->getJwtKey(), self::JWT_ALGORITHM);
        }
        return null;
    }

    /**
     * @return array
     */
    private function getJwtPayload()
    {
        $timestamp = time();
        return [
            'iss' => 'selfoss',
            'exp' => $timestamp + $this->getAdditionalExpiringInSeconds(),
            'iat' => $timestamp,
            'auth' => $this->isLoggedIn()
        ];
    }

    /**
     * @return mixed
     */
    private function getJwtKey()
    {
        return \F3::get('jwt_key');
    }

    /**
     * @return object
     */
    private function getDecodedPayload()
    {
        try {
            $token = $this->getTokenFromHeader();
            if ($token !== null) {
                return JWT::decode($token, $this->getJwtKey(), [self::JWT_ALGORITHM]);
            }
            \F3::get('logger')->debug('no valid token in header.');
            return null;
        }
        catch (\Exception $e) {
            \F3::get('logger')->debug('error on payload decode: ' .  $e->getMessage());
            return null;
        }

    }

    /**
     * @return string|null
     */
    private function getTokenFromHeader()
    {
        $headers = \F3::get('HEADERS');
        $authHeader = isset($headers['Authorization']) ? trim($headers['Authorization']) : '';
        if ($authHeader !== '' && strpos($authHeader, 'Bearer') === 0) {
            return trim(substr($authHeader, 6));
        }
        return null;
    }

    /**
     * @return int
     */
    private function getAdditionalExpiringInSeconds()
    {
        return (int) \F3::get('jwt_exp');
    }
}
