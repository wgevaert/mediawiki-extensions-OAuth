<?php

/**
 * @author	  Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license	 http://mit-license.org/
 *
 * @link		https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenValidators;

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

class TokenValidationResult
{
	public function __construct( private string|null $userId ) {
	}

	public static function newFromValues(array $values) {
		return new self(
			$values['user_id'] ?? null,
		);
	}
	
	public function getUserId(): ?string {
		return $this->userId;
	}
}
