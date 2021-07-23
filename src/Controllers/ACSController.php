<?php

/*
 * This file is part of askvortsov/flarum-saml
 *
 *  Copyright (c) 2021 Alexander Skvortsov.
 *
 *  For detailed copyright and license information, please view the
 *  LICENSE file that was distributed with this source code.
 */

namespace Askvortsov\FlarumSAML\Controllers;

use Askvortsov\FlarumAuthSync\Models\AuthSyncEvent;
use Askvortsov\FlarumSAML\SAMLTrait;
use Carbon\Carbon;
use Flarum\Extension\ExtensionManager;
use Flarum\Forum\Auth\Registration;
use Flarum\Forum\Auth\ResponseFactory;
use Flarum\Settings\SettingsRepositoryInterface;
use Laminas\Diactoros\Response\HtmlResponse;
use OneLogin\Saml2\Constants;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface;
use Flarum\User\UserRepository;
use Flarum\User\User;

class ACSController implements RequestHandlerInterface
{
    use SAMLTrait;

    /**
     * @var ResponseFactory
     */
    protected $response;

    /**
     * @var SettingsRepositoryInterface
     */
    protected $settings;

    /**
     * @var ExtensionManager
     */
    protected $extensions;

    protected $users;

    public function __construct(ResponseFactory $response, SettingsRepositoryInterface $settings, ExtensionManager $extensions, UserRepository $users)
    {
        $this->response = $response;
        $this->settings = $settings;
        $this->extensions = $extensions;
	$this->users = $users;
    }

    public function handle(Request $request): Response
    {
        try {
            $saml = $this->auth(true);
        } catch (\Exception $e) {
            resolve('log')->error($e->getMessage());

            return new HtmlResponse('Invalid SAML Configuration: Check Settings');
        }

        try {
            $saml->processResponse();
        } catch (\Exception $e) {
            resolve('log')->error($e->getMessage());

            return new HtmlResponse('Could not process response: '.$e->getMessage());
        }
        if (!empty($saml->getErrors())) {
            $errors = implode(', ', $saml->getErrors());

            return new HtmlResponse('Could not process response: '.$errors.': '.$saml->getLastErrorReason());
        }
        if (!$saml->isAuthenticated()) {
            return new HtmlResponse('Authentication Failed');
        }

        $is_email_auth = $saml->getNameIdFormat() === Constants::NAMEID_EMAIL_ADDRESS;

        $attributes = [];
        foreach ($saml->getAttributes() as $key => $val) {
            $attributes[$key] = $val[0];
        }

        if ($is_email_auth) {
            $email = filter_var($saml->getNameId(), FILTER_VALIDATE_EMAIL);
        } else {
            $email = filter_var($attributes['urn:oid:1.2.840.113549.1.9.1.1'], FILTER_VALIDATE_EMAIL);
            unset($attributes['urn:oid:1.2.840.113549.1.9.1.1']);
            if (!isset($email)) {
                $email = filter_var($attributes['email'], FILTER_VALIDATE_EMAIL);
            }
        }

        if (!isset($email)) {
            return new HtmlResponse('Email not provided.');
        }

        $masquerade_attributes = [];
        foreach ($attributes as $key => $attribute) {
            if ($key != 'avatar' && $key != 'bio' && $key != 'groups') {
                $masquerade_attributes[$key] = $attribute;
            }
        }

        $avatar = $saml->getAttribute('avatar')[0];
        $username = $saml->getAttribute('username')[0];

        if ($this->extensions->isEnabled('askvortsov-auth-sync') && $this->settings->get('askvortsov-saml.sync_attributes', false)) {
            $event = new AuthSyncEvent();
            $event->email = $email;
            $event->attributes = json_encode([
                'avatar'                => $avatar,
                'bio'                   => $saml->getAttribute('bio')[0],
                'groups'                => explode(',', $saml->getAttribute('groups')[0]),
                'masquerade_attributes' => $masquerade_attributes,
            ]);
            $event->time = Carbon::now();
            $event->save();
        }

        $u = $this->users->findByEmail($email);
        if ($u == null) {
             $password = $this->generateStrongPassword();
             $u = User::register($username, $email, $password);
             $u->activate();
             $u->save();
        }

        return $this->response->make(
            'saml-sso',
            $saml->getNameId(),
            function (Registration $registration) use ($avatar, $email) {
                $registration
                    ->provideTrustedEmail($email)
                    ->suggestUsername('')
                    ->setPayload([]);

                if ($avatar) {
                    $registration->provideAvatar($avatar);
                }
            }
        );
    }
  
    private function generateStrongPassword($length = 9, $add_dashes = false, $available_sets = 'luds')
    {
        $sets = array();
        if (strpos($available_sets, 'l') !== false) {
            $sets[] = 'abcdefghjkmnpqrstuvwxyz';
        }
        if (strpos($available_sets, 'u') !== false) {
            $sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';
        }
        if (strpos($available_sets, 'd') !== false) {
            $sets[] = '23456789';
        }
        if (strpos($available_sets, 's') !== false) {
            $sets[] = '!@#$%&*?';
        }

        $all = '';
        $password = '';
        foreach ($sets as $set) {
            $password .= $set[array_rand(str_split($set))];
            $all .= $set;
        }

        $all = str_split($all);
        for ($i = 0; $i < $length - count($sets); $i++) {
            $password .= $all[array_rand($all)];
        }

        $password = str_shuffle($password);

        if (!$add_dashes) {
            return $password;
        }

        $dash_len = floor(sqrt($length));
        $dash_str = '';
        while (strlen($password) > $dash_len) {
            $dash_str .= substr($password, 0, $dash_len) . '-';
            $password = substr($password, $dash_len);
        }
        $dash_str .= $password;
        return $dash_str;
    }

}
