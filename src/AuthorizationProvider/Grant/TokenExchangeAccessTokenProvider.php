<?php

namespace MediaWiki\Extension\OAuth\AuthorizationProvider\Grant\TokenExchange;

use League\OAuth2\Server\Grant\GrantTypeInterface;
use MediaWiki\Extension\OAuth\AuthorizationProvider\AccessTokenProvider;

/**
 * Provides access tokens for a client credentials grant.
 */
class TokenExchangeAccessTokenProvider extends AccessTokenProvider {
	/**
	 * @return GrantTypeInterface
	 */
	protected function getGrant(): GrantTypeInterface {
		$grant = new TokenExchangeGrantWithCustomClaims();
		$policyRepository = $this->getTokenExchangePolicyRepository();
		$grant->setTokenExchangePolicyRepository( $policyRepository );
		return $grant;
	}

	protected function getTokenExchangePolicyRepository(): TokenExchangePolicyRepository {
                $oauthConfig = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'mwoauth' );
                // Private key to sign the token
                $privateKey = new CryptKey(
                        $this->config->get( 'OAuth2PrivateKey' ),
                        $this->config->get( 'OAuth2Passphrase' )
                );
		$accessTokenRepo = OAuthServices::wrap( MediaWikiServices::getInstance() )->getAccessTokenRepository();

		$policy = new JwtToAccessTokenExchangePolicy(
	                $this->config->get('OAuthTokenExchangeJwtPublicKey'),
	                $this->config->get('OAuthTokenExchangeJwtIssuer'),
	                $this->config->get('OAuthTokenExchangeJwtAudience'),
			$privateKey,
			$accessTokenRepo
		);
		return new SimpleTokenExchangePolicyRepository($policy)
	}
}
