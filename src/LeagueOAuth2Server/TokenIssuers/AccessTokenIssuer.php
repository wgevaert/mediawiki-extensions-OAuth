<?php

namespace MediaWiki\Extension\OAuth\LeagueOAuth2Server\TokenIssuers;

use Psr\Http\Message\ServerRequestInterface;

class AccessTokenIssuer implements TokenIssuer {
    protected CryptKeyInterface $privateKey;

    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository): void
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * Set the private key
     */
    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    /**
     * Issue an access token.
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        string|null $userIdentifier,
        array $scopes = [],
	?ServerWebRequest $request = null,
    ): AccessTokenEntityInterface {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $accessToken = $this->accessTokenRepository->getNewToken($client, $scopes, $userIdentifier);
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add($accessTokenTTL));
        $accessToken->setPrivateKey($this->privateKey);

        while ($maxGenerationAttempts-- > 0) {
            $accessToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($accessToken);

                return $accessToken;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        // This should never be hit. It is here to work around a PHPStan false error
        return $accessToken;
    }

    /**
     * Generate a new unique identifier.
     *
     * @return non-empty-string
     *
     * @throws OAuthServerException
     */
    protected function generateUniqueIdentifier(int $length = 40): string
    {
        try {
            if ($length < 1) {
                throw new DomainException('Length must be a positive integer');
            }

            return bin2hex(random_bytes($length));
            // @codeCoverageIgnoreStart
        } catch (TypeError | Error $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred', $e);
        } catch (Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw OAuthServerException::serverError('Could not generate a random string', $e);
        }
        // @codeCoverageIgnoreEnd
    }
}
