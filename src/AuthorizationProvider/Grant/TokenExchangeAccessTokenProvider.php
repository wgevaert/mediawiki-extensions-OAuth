<?php

namespace MediaWiki\Extension\OAuth\AuthorizationProvider\Grant;

use MediaWiki\MediaWikiServices;
use MediaWiki\Extension\OAuth\Repository\AccessTokenRepository;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\Grant\TokenExchangeGrant;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\Repositories\SimpleTokenExchangePolicyRepository;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\Repositories\TokenExchangePolicyRepositoryInterface;
use MediaWiki\Extension\OAuth\OAuthServices;
use MediaWiki\Extension\OAuth\Pega\JwtToAccessTokenExchangePolicy;
use MediaWiki\Extension\OAuth\AuthorizationProvider\AccessToken as AccessTokenProvider;

/**
 * Provides access tokens for a client credentials grant.
 */
class TokenExchangeAccessTokenProvider extends AccessTokenProvider {
	/**
	 * @return GrantTypeInterface
	 */
	protected function getGrant(): GrantTypeInterface {
		$policyRepository = $this->getTokenExchangePolicyRepository();
		return new TokenExchangeGrant($policyRepository);
		return $grant;
	}

	protected function getTokenExchangePolicyRepository(): TokenExchangePolicyRepositoryInterface {
		$oauthConfig = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'mwoauth' );

                // Private key to sign the token
                $privateKey = new CryptKey(
                        $oauthConfig->get( 'OAuth2PrivateKey' ),
                        $oauthConfig->get( 'OAuth2Passphrase' )
                );
		$accessTokenRepo = new AccessTokenRepository( $this->config->get( 'CanonicalServer' ) ); // OAuthServices::wrap( MediaWikiServices::getInstance() )->getAccessTokenRepository();

		$policy = new JwtToAccessTokenExchangePolicy(
	                $oauthConfig->get('OAuthTokenExchangeJwtIssuer'),
	                $oauthConfig->get('OAuthTokenExchangeJwtAudience'),
			$privateKey,
			$accessTokenRepo
		);
		return new SimpleTokenExchangePolicyRepository($policy);
	}
}
