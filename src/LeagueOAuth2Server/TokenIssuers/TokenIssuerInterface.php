<?php

declare(strict_types=1);

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenIssuers;

use DateInterval;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\TokenInterface;

interface TokenIssuerInterface
{
	/**
	 * Issue a token
	 *
	 * @param DateInterval $tokenTTL How long the token should be valid.
	 * @param ClientEntityInterface The client from whom this token is issued.
	 * @param string|null $userIdentifier The user to issue the token for, if any.
	 * @param ScopeEntityInterface[] $scopes The scopes this token should provide.
	 * @param string|null $actorIdentifier The actor in token exchange who will use the token, if any.
	 * @param ServerRequestInterface|null $request The request for retrieving any possibly relevant other parameters.
	 * @return TokenInterface
	 * @throws OAuthException When the token could not be issued for any reason.
	 */
	public function issueToken(
	        DateInterval $tokenTTL,
        	ClientEntityInterface $client,
	        string|null $userIdentifier,
        	array $scopes = [],
		string|null $actorIdentifier,
	        ?ServerRequestInterface $request = null,
	): TokenInterface;
}
