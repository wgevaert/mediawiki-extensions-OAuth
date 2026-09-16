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
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Exception;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators\TokenValidationResult;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators\TokenValidatorInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

use function base64_decode;
use function date_default_timezone_get;
use function preg_replace;
use function trim;

/**
 * A validator for Jwt tokens
 */
class JwtValidator implements TokenValidatorInterface
{
	protected string $publicKey;

	private string $audience;
	private string $jwksEndpoint;
	private array $issuers = [];

	public function __construct(private ?DateInterval $jwtValidAtDateLeeway = null)
	{
		//TODO: inject
		$this->jwksEndpoint = 'https://itappfactory-dt2.cloud.pega.net/prweb/PRRestService/keys/v1/jwt/PPFToRemoteTokenGeneration';
       	}

	public function setAudience( string $audience ): void {
		$this->audience = $audience;
	}

	public function addIssuer( string $issuer ): void {
		$this->issuers []= $issuer;
	}

	/**
	 * {@inheritdoc}
	 */
	public function validateToken( string $jwt ): TokenValidationResult
	{
		if ($jwt === '') {
			throw OAuthServerException::accessDenied('Received empty JWT');
		}
		if (substr_count($jwt, '.' ) < 2) {
			throw OAuthServerException::accessDenied('Received invalid JWT');
		}

		[ $headerEncoded, $tokenEncoded, $signatureEncoded ] = explode( '.', $jwt, 3 ); 

		$header = $this->jsonDecodeBase64Url($headerEncoded);
		$claims = $this->jsonDecodeBase64Url($tokenEncoded);
		$key = $this->getKeyForHeader( $header );

		// Check signature
		/**
		 * POC: Skip this. TODO!!!!! IMPLEMENT
		 */

		// Check issuer
		$iss = $claims->iss;
		if ( !in_array( $iss, $this->issuers ) ) {
			throw OAuthServerException::accessDenied( 'JWT has not been issued by a recognised issuer' );
		}

		// Check audience
		$audienceId = $this->getAudienceIdForIssuer( $iss );
		if ( $audienceId && !in_array( $audienceId, $claims->aud ) ) {
			throw OAuthServerException::accessDenied( 'JWT has not been issued for a known audience' );
		}

		// Check if token has been revoked
		// TODO: Check also for tokens that are not ours maybe?
		// POC: skip for POC
		/*
		if ($this->accessTokenRepository->isAccessTokenRevoked($claims->jti)) {
			throw OAuthServerException::accessDenied('JWT has been revoked');
		}*/

		// TODO: Make a return value that makes sense.
		return TokenValidationResult::fromValues([
			'access_token_id' => $claims->jti,
			'client_id' => $claims->aud[0],
			'user_id' => $claims->sub,
			'scopes' => $claims->scopes,
		]);
	}

	protected function getAudienceIdForIssuer( $iss ) {
		// TODO: For different issuers you may be known as a different audience
		return $this->audience;
	}

	protected function getKeyForHeader($header) {
		$keysJson = file_get_contents($this->jwksEndpoint);
		$keys = json_decode( $keysJson, false, 512, JSON_THROW_ON_ERROR );
		foreach ($keys as $key) {
			if ($key->kid === $header->kid && $key->alg === $header->alg) {
				return $key;
			}
		}
		OAuthServerException::accessDenied('JWT has unknown kid');
	}

	private function b64url2b64(string $base64url): string
	{
	    // "Shouldn't" be necessary, but why not
	    $padding = strlen($base64url) % 4;
	    if ($padding > 0) {
	        $base64url .= str_repeat('=', 4 - $padding);
	    }
	    return strtr($base64url, '-_', '+/');
	}

	private function base64_decode_url(string $base64url): string {
		return base64_decode($this->b64url2b64($base64url));
	}

	private function jsonDecodeBase64Url( string $base64url ) {
		return json_decode($this->base64_decode_url($base64url), false, 512, JSON_THROW_ON_ERROR);
	}
}
