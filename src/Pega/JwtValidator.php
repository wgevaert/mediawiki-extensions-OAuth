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
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators\TokenValidationResult;
use MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators\TokenValidatorInterface;
use MediaWiki\Extension\OAuth\Backend\Utils;
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
class JwtValidator extends AbstractJwtValidator implements TokenValidatorInterface
{
	protected string $publicKey;

	private string $audience;
	private string $jwksEndpoint;
	private $userId = null;

	public function __construct(private ?DateInterval $jwtValidAtDateLeeway = null)
	{
		//TODO: inject
		$this->setJwksUri( 'https://itappfactory-dt2.cloud.pega.net/prweb/PRRestService/keys/v1/jwt/PPFToRemoteTokenGeneration' );
       	}

	public function setAudience( string $audience ): void {
		$this->audience = $audience;
	}

	/**
	 * @inheritdoc
	 */
	protected function validateAudience( $audience ): bool {
		return $audience === $this->audience;
	}

	protected function validateSubject( $sub ): bool {
		if ( !str_ends_with($sub, '@pegasystems.com') ) {
			return false;
		}
		$this->userId = $this->translateSubToUserId($sub);
		return true;
	}

	protected function validateJti( $jti ): bool {
		// We do allow replays
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function validateToken( string $jwt ): TokenValidationResult
	{
		$this->userId = null;
		if ($jwt === '') {
			throw OAuthServerException::accessDenied('Received empty JWT');
		}
		try {
			$result = $this->validateJwtToken($jwt);
			if (!$result) {
				throw OAuthServerException::accessDenied("Invalid JWT");
			}
		} catch (JwtValidatorException $e) {
			throw OAuthServerException::accessDenied("Could not validate JWT: " . $e->getMessage());
		}
		$claims = $this->verifiedClaims;

		// TODO: Make a return value that makes sense.
		$result = TokenValidationResult::fromValues([
			'access_token_id' => $claims->jti,
			'client_id' => $claims->aud[0],
			'user_id' => $this->userId,
			'scopes' => $claims->scopes,
		]);
		return $result;
	}

	private function translateSubToUserId(string $sub): int {
		$pegaId = substr($sub,0,strlen($sub) - strlen('@pegasystems.com'));
		$userId = Utils::getCentralIdFromUserName( ucfirst(strtolower($pegaId)));

		return $userId;
	}
}
