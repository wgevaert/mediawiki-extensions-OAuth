<?php

/**
 * @author	  Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license	 http://mit-license.org/
 *
 * @link		https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\AuthorizationValidators;

use Psr\Http\Message\ServerRequestInterface;

interface TokenValidatorInterface
{
	/**
	 * Validates the token. Different validators may be suitable for different types of tokens.
	 */
	public function validateToken(string $token): TokenValidationResponse;
}
