<?php

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\Repositories;

use League\OAuth2\Server\Repositories\RepositoryInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenExchange\TokenExchangePolicyInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\RequestTypes\TokenExchangeRequestInterface;


interface TokenExchangePolicyRepositoryInterface extends RepositoryInterface {
	/**
	 * Determines the token exchange policy to apply
	 *
	 * Can use request parameters such as
	 * requested_token_type, resource, audience and scope
	 * to determine this.
	 *
	 * @throws OAuthServerException
	 * @return TokenExchangePolicyInterface|null The policy to use, or null if no policy could be determined.
	 */
	public function getPolicyFromRequest( ?TokenExchangeRequestInterface $request ): ?TokenExchangePolicyInterface;
}
