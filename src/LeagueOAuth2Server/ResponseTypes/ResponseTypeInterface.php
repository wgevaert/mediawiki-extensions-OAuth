<?php

/**
 * OAuth 2.0 Response Type Interface.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\ResponseType;

use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface as LeagueResponseTypeInterface;

interface ResponseTypeInterface extends LeagueResponseTypeInterface
{
    public function setTokenType(string $tokenType): void;
}
