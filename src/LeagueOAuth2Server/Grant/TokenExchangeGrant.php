<?php

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\Grant;

use DateInterval;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators\TokenValidationResult;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\Repositories\TokenExchangePolicyRepositoryInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface as LeagueResponseTypeInterface;
use League\OAuth2\Server\RequestEvent;

class TokenExchangeGrant extends AbstractGrant {
	protected TokenExchangePolicyRepositoryInterface $tokenExchangePolicyRepository;

	public function __construct(
		TokenExchangePolicyRepositoryInterface $tokenExchangePolicyRepository
	) {
		$this->setTokenExchangePolicyRepository( $tokenExchangePolicyRepository );
	}

	public function getIdentifier(): string
	{
		return 'urn:ietf:params:oauth:grant-type:token-exchange';
	}

	public function setTokenExchangePolicyRepository( TokenExchangePolicyRepositoryInterface $tokenExchangePolicyRepository ): void {
		$this->tokenExchangePolicyRepository = $tokenExchangePolicyRepository;
	}

	/**
	 * Respond to an incoming request.
	 */
	public function respondToAccessTokenRequest(
		ServerRequestInterface $request,
		LeagueResponseTypeInterface $responseType,
		DateInterval $accessTokenTTL
	): ResponseTypeInterface {
		$client = $this->validateAuthenticatedClient( $request );

		$tokenExchangeRequest = $this->validateTokenExchangeRequest( $request );
		$policy = $this->tokenExchangePolicyRepository->getPolicyFromRequest( $tokenExchangeRequest );

		$subjectTokenData = $this->validateSubjectToken( $request, $policy );
		$actorTokenData = $this->validateOptionalActorToken( $request, $policy );

		$requestedTokenType = $this->getRequestParameter( 'requested_token_type', $request ) ?? $policy->determineRequestedTokenType();
		if ( !$policy->authorizeRequest( $subjectTokenData, $actorTokenData, $requestedTokenType ) ) {
			throw OAuthServerException::accessDenied('you do not have access');
		}
		$newToken = $policy->getTokenIssuer(
			$requestedTokenType
		)->issueToken(
			$accessTokenTTL,
			$client,
			$subjectTokenData->getUserId(),
			$finalizedScopes ?? [], //TODO: finalize scopes
			$actorTokenData?->getUserId(),
			$request
		);

		$responseType->setAccessToken( $newToken );
		$responseType->setTokenType( $requestedTokenType );

		return $responseType;
	}

	protected function validateTokenExchangeRequest( ServerRequestInterface $request ): void /*POC: replaced with void TokenExchangeRequestInterface*/ {
		$subjectToken = $this->getRequestParameter( 'subject_token', $request );
		$subjectTokenType = $this->getRequestParameter( 'subject_token_type', $request );

		if ( $subjectToken === null ) {
			$this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

			throw OAuthServerException::invalidRequest('subject_token');
		}
		if ( $subjectTokenType === null ) {
			$this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

			throw OAuthServerException::invalidRequest('subject_token_type');
		}

		$actorToken = $this->getRequestParameter( 'actor_token', $request );
		$actorTokenType = $this->getRequestParameter( 'actor_token_type', $request );

		// Actor token type should only be provided if actor token is also provided.
		if ( $actorToken !== null && $actorTokenType === null ) {
			$this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

			throw OAuthServerException::invalidRequest( 'actor_token_type' );
		} elseif ( $actorToken === null && $actorTokenType !== null ) {
			$this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

			throw OAuthServerException::invalidRequest( '', 'An actor_token_type was given without an actor_token' );
		}

		// All other parameters are optional, so no validation is needed on those.
	}

	/**
	 * A wrapper around validateClient that makes sure the client is authenticated.
	 *
	 * Override this function to support other methods of client authentication.
	 *
	 * Note that RFC 8693 warns about allowing non-authenticated clients:
	 * > omitting client authentication allows for a compromised token to be leveraged
	 * > via an STS into other tokens by anyone possessing the compromised token.
	 *
	 * @throws OAuthServerException
	 */
	protected function validateAuthenticatedClient(ServerRequestInterface $request): ClientEntityInterface {
		$client = $this->validateClient( $request );

		// validateClient will have checked client credentials for confidential clients, so we only check that it is indeed a confidential client.
		if ( !$client->isConfidential() ) {
			$this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

			throw OAuthServerException::invalidClient( $request );
		}

		return $client;
	}

	protected function validateSubjectToken( $request, $policy ): TokenValidationResult {
		$subjectTokenType = $this->getRequestParameter( 'subject_token_type', $request );
		$subjectToken = $this->getRequestParameter( 'subject_token', $request );

		if ( !$policy->isAllowedSubjectTokenType( $subjectTokenType ) ) {
			throw OAuthServerException::invalidRequest('subject_token_type');
		}

		return $policy->getSubjectTokenValidator($subjectTokenType)->validateToken($subjectToken);
	}

	protected function validateOptionalActorToken( $request, $policy ): ?TokenValidationResult {
		$actorTokenType = $this->getRequestParameter( 'actor_token_type', $request );
		$actorToken = $this->getRequestParameter( 'actor_token', $request );
		if ( $actorToken === null ) {
			if ( $policy->requiresActorToken() ) {
				throw OAuthServerException::invalidRequest('actor_token');
			}
			return null;
		}

		if ( !$policy->isAllowedActorTokenType( $actorTokenType ) ) {
			throw OAuthServerException::invalidRequest('actor_token_type');
		}

		return $policy->getActorTokenValidator($actorTokenType)->validateToken($actorToken);
	}
}
