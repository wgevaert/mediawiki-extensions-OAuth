<?php

/**
 * @author	  Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license	 http://mit-license.org/
 *
 * @link		https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace MediaWiki\Extension\OAuth\Pega;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Exception;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

use function date_default_timezone_get;
use function preg_replace;
use function trim;

/**
 * A validator for Jwt tokens
 */
class JwtTokenValidator implements TokenValidatorInterface
{
	use CryptTrait;

	protected CryptKeyInterface $publicKey;

	private Configuration $jwtConfiguration;
	private string $audience;
	private array $issuers = [];

	public function __construct(private ?DateInterval $jwtValidAtDateLeeway = null)
	{
	}

	public function setAudience( string $audience ): void {
		$this->audience = $audience;
	}

	public function addIssuer( string $issuer ): void {
		$this->issuers []= $issuer;
	}

	/**
	 * Set the public key
	 */
	public function setPublicKey(CryptKeyInterface $key): void
	{
		$this->publicKey = $key;

		$this->initJwtConfiguration();
	}

	/**
	 * Initialise the JWT configuration.
	 */
	private function initJwtConfiguration(): void
	{
		$this->jwtConfiguration = Configuration::forSymmetricSigner(
			new Sha256(),
			InMemory::plainText('empty', 'empty')
		);

		$clock = new class () implements ClockInterface {
			public function now(): DateTimeImmutable
			{
				return new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get()));
			}
		};

		$publicKeyContents = $this->publicKey->getKeyContents();

		if ($publicKeyContents === '') {
			throw new RuntimeException('Public key is empty');
		}

		// TODO: next major release: replace deprecated method and remove phpstan ignored error
		$this->jwtConfiguration->setValidationConstraints(
			new LooseValidAt($clock, $this->jwtValidAtDateLeeway),
			new SignedWith(
				new Sha256(),
				InMemory::plainText($publicKeyContents, $this->publicKey->getPassPhrase() ?? '')
			)
		);
	}

	/**
	 * {@inheritdoc}
	 */
	public function validateToken( string $jwt ): TokenValidationResult
	{
		if ($jwt === '') {
			throw OAuthServerException::accessDenied('Missing "Bearer" token');
		}

		try {
			// Attempt to parse the JWT
			$token = $this->jwtConfiguration->parser()->parse($jwt);
		} catch (Exception $exception) {
			throw OAuthServerException::accessDenied($exception->getMessage(), null, $exception);
		}

		try {
			// Attempt to validate the JWT
			$constraints = $this->jwtConfiguration->validationConstraints();
			$this->jwtConfiguration->validator()->assert($token, ...$constraints);
		} catch (RequiredConstraintsViolated $exception) {
			throw OAuthServerException::accessDenied('Access token could not be verified', null, $exception);
		}

		if (!$token instanceof UnencryptedToken) {
			throw OAuthServerException::accessDenied('Access token is not an instance of UnencryptedToken');
		}

		$claims = $token->claims();

		// Check issuer
		$iss = $claims->get('iss');
		if ( !in_array( $iss, $this->issuers ) ) {
			throw OAuthServerException::accessDenied( 'Access token has not been issued by a recognised issuer' );
		}

		// Check audience
		$audienceId = $this->getAudienceIdForIssuer( $iss );
		if ( $audienceId && !in_array( $audienceId, $claims->get('aud') ) ) {
			throw OAuthServerException::accessDenied( 'Access token has not been issued for a known audience' );
		}

		// Check if token has been revoked
		// TODO: Check also for tokens that are not ours maybe?
		// POC: skip for POC
		/*
		if ($this->accessTokenRepository->isAccessTokenRevoked($claims->get('jti'))) {
			throw OAuthServerException::accessDenied('Access token has been revoked');
		}*/

		// TODO: Make a return value that makes sense.
		return TokenValidationResult::fromValues([
			'access_token_id' => $claims->get('jti'),
			'client_id' => $claims->get('aud')[0],
			'user_id' => $claims->get('sub'),
			'scopes' => $claims->get('scopes'),
		]);
	}

	protected function getAudienceIdForIssuer( $iss ) {
		// TODO: For different issuers you may be known as a different audience
		return $this->audience;
	}
}
