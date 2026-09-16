<?php

namespace MediaWiki\Extension\OAuth\Pega;

use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenExchange\TokenExchangePolicyInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators\TokenValidatorInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenIssuers\TokenIssuerInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenIssuers\AccessTokenIssuer;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators\TokenValidationResult;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenExchange\TokenType;

class JwtToAccessTokenExchangePolicy implements TokenExchangePolicyInterface {
	public function __construct(
		private string $jwtIssuer,
		private string $audience,
		private $privateKey,
		private $accessTokenRepository,
	) {
	}

	public function isAllowedSubjectTokenType( string $subjectTokenType ): bool {
		return $subjectTokenType === TokenType::JWT;
	}

	public function getSubjectTokenValidator( string $subjectTokenType ): TokenValidatorInterface {
		$validator = new JwtValidator;
		$validator->addIssuer( $this->jwtIssuer );
		$validator->setAudience( $this->audience );
		return $validator;
	}

	public function requiresActorToken(): bool {
		return false;
	}

	public function isAllowedActorTokenType( string $actorTokenType ): bool {
		return $actorTokenType === TokenType::JWT;
	}

	public function getActorTokenValidator( $actorTokenType ): TokenValidatorInterface {
		throw new LogicException( 'not implemented' );
	}

	public function determineRequestedTokenType(): string {
		return TokenType::ACCESS_TOKEN;
	}

	public function getTokenIssuer(string $requestedTokenType): TokenIssuerInterface {
		if ( $requestedTokenType !== TokenType::ACCESS_TOKEN ) {
			throw OAuthServerException::invalidRequest('requested_token_type');
		}
		$issuer = new AccessTokenIssuer;
		$issuer->setAccessTokenRepository( $this->accessTokenRepository );
		$issuer->setPrivateKey( $this->privateKey );
		return $issuer;
	}

	public function authorizeRequest(
		TokenValidationResult $subjectToken,
		?TokenValidationResult $actorToken,
		string $requestedTokenType,
		// More parameters are probably needed...
	): bool {
		// TODO!!!!!! Check scopes maybe?
		return true;
	}
}
