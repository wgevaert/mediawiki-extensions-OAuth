<?php

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\Repositories; 

use League\OAuth2\Server\Repositories\RepositoryInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\RequestTypes\TokenExchangeRequestInterface;

class SimpleTokenExchangePolicyRepository extends TokenExchangePolicyRepositoryInterface {
	public function __construct( private TokenExchangePolicyInterface $tokenExchangePolicy ) {
	}

	public function getPolicyFromRequest( TokenExchangeRequestInterface $request ): ?TokenExchangePolicyInterface {
		return $this->tokenExchangePolicy;
	}
}
