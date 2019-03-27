<?php
/**
 * Created by PhpStorm.
 * User: cnagel
 * Date: 3/27/19
 * Time: 3:58 PM
 */

namespace helpers\Authentication;


interface ProviderInterface
{
    /**
     * @return bool
     */
    public function isLoggedIn();


    /**
     * @return void
     */
    public function logout();


    /**
     * @return void
     */
    public function login();


    /**
     * @return void
     */
    public function initialize();


    /**
     * @return string|null
     */
    public function getPayload();
}
