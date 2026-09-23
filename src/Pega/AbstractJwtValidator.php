<?php
/**
 * Modified from JumboJett OpenIDConnectClient, which had the following license:
 *
 * Copyright MITRE 2020
 *
 * OpenIDConnectClient for PHP7+
 * Author: Michael Jett <mjett@mitre.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

namespace MediaWiki\Extension\OAuth\Pega;

use Error;
use Exception;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use stdClass;
use function bin2hex;
use function is_object;
use function random_bytes;

/**
 * JwtValidator Exception Class
 */
class JwtValidatorException extends Exception
{
}

/**
 *
 * Please note this class stores nonces by default in $_SESSION['openid_connect_nonce']
 *
 */
abstract class AbstractJwtValidator
{
	/**
	 * @var int timeout (seconds)
	 */
	protected $timeOut = 60;

	/**
	 * @var int leeway (seconds)
	 */
	private $leeway = 300;

	// Set allowed token age per default on 365 days
	private $allowedTokenAge = 365 * 24 * 60 * 60;

	/**
	 * @var array holds response types
	 */
	private $additionalJwks = [];

	/**
	 * @var object holds verified jwt claims
	 */
	protected $verifiedClaims = [];

	/**
	 * @var callable|null validator function for issuer claim
	 */
	private $issuerValidator;

	/**
	 * @param string|null $provider_url optional
	 * @param string|null $issuer
	 */
	public function __construct(private ?string $issuer = null, private ?string $jwksUri = null) {
	}

	/**
	 * @param $issuer
	 */
	public function setIssuer($issuer) {
		$this->issuer = $issuer;
	}

	public function setJwksUri($jwksUri) {
		$this->jwksUri = $jwksUri;
	}

	public function validateJwtToken($id_token) {
		$this->verifiedClaims = [];
		$idTokenHeaders = $this->decodeJWT($id_token);
		if (isset($idTokenHeaders->enc)) {
			// Handle JWE
			$id_token = $this->handleJweResponse($id_token);
		}

		$claims = $this->decodeJWT($id_token, 1);

		// Verify the signature
		$this->verifySignatures($id_token);

		// If this is a valid claim
		if ($this->verifyJWTClaims($claims)) {

			// Save the verified claims
			$this->verifiedClaims = $claims;

			// Success!
			return true;
		}
		return false;
	}

	/**
	 * @param $jwk object - example: (object) ['kid' => ..., 'nbf' => ..., 'use' => 'sig', 'kty' => "RSA", 'e' => "", 'n' => ""]
	 */
	protected function addAdditionalJwk($jwk) {
		$this->additionalJwks[] = $jwk;
	}

	/**
	 * @throws JwtValidatorException
	 */
	private function getKeyForHeader(array $keys, stdClass $header) {
		foreach ($keys as $key) {
			if ($this->headerMatchesKey($key, $header) ) {
				return $key;
			}
		}
		if (isset($header->kid)) {
			throw new JwtValidatorException('Unable to find a key for (algorithm, kid):' . $header->alg . ', ' . $header->kid . ')');
		}

		throw new JwtValidatorException('Unable to find a key for RSA');
	}

	private function headerMatchesKey(stdClass $key, stdClass $header ): bool {
		if ($key->kty === 'RSA') {
			if (!isset($header->kid) || $key->kid === $header->kid) {
				return true;
			}
		} else if (isset($key->alg) && $key->alg === $header->alg && $key->kid === $header->kid) {
			return true;
		}
		return false;
	}

	/**
	 * @throws JwtValidatorException
	 */
	private function verifyRSAJWTSignature(string $hashType, stdClass $key, $payload, $signature, $signatureType): bool
	{
		if (!(property_exists($key, 'n') && property_exists($key, 'e'))) {
			throw new JwtValidatorException('Malformed key object');
		}

		$key = RSA::load([
			'publicExponent' => new BigInteger($this->base64url_decode($key->e), 256),
			'modulus' => new BigInteger($this->base64url_decode($key->n), 256),
			'isPublicKey' => true,
		])
			->withHash($hashType);
		if ($signatureType === 'PSS') {
			$key = $key->withMGFHash($hashType)->withPadding(RSA::SIGNATURE_PSS);
		} else {
			$key = $key->withPadding(RSA::SIGNATURE_PKCS1);
		}
		return $key->verify($payload, $signature);
	}

	private function verifyHMACJWTSignature(string $hashType, string $key, string $payload, string $signature): bool
	{
		$expected = hash_hmac($hashType, $payload, $key, true);
		return hash_equals($signature, $expected);
	}

	/**
	 * @param string $jwt encoded JWT
	 * @return bool
	 * @throws JwtValidatorException
	 */
	public function verifyJWTSignature(string $jwt): bool
	{
		$parts = explode('.', $jwt);
		if (!isset($parts[0])) {
			throw new JwtValidatorException('Error missing part 0 in token');
		}
		$signature = $this->base64url_decode(array_pop($parts));
		if (false === $signature || '' === $signature) {
			throw new JwtValidatorException('Error decoding signature from token');
		}
		$header = json_decode($this->base64url_decode($parts[0]), false);
		if (!is_object($header)) {
			throw new JwtValidatorException('Error decoding JSON from token header');
		}
		if (!isset($header->alg)) {
			throw new JwtValidatorException('Error missing signature type in token header');
		}

		$payload = implode('.', $parts);
		switch ($header->alg) {
		case 'RS256':
		case 'PS256':
		case 'PS512':
		case 'RS384':
		case 'RS512':
			$hashType = 'sha' . substr($header->alg, 2);
			$signatureType = $header->alg === 'PS256' || $header->alg === 'PS512' ? 'PSS' : '';
			if (isset($header->jwk)) {
				$jwk = $header->jwk;
				$this->verifyJWKHeader($jwk);
			} else {
				$keys = $this->getPossibleJwks();
				$jwk = $this->getKeyForHeader($keys, $header);
			}

			$verified = $this->verifyRSAJWTSignature($hashType,
				$jwk,
				$payload, $signature, $signatureType);
			break;
		case 'HS256':
		case 'HS512':
		case 'HS384':
			$hashType = 'SHA' . substr($header->alg, 2);
			$verified = $this->verifyHMACJWTSignature($hashType, $this->getClientSecret(), $payload, $signature);
			break;
		default:
			throw new JwtValidatorException('No support for signature type: ' . $header->alg);
		}
		return $verified;
	}

	/**
	 * @param string $jwt encoded JWT
	 * @return void
	 * @throws JwtValidatorException
	 */
	public function verifySignatures(string $jwt)
	{
		if (!$this->verifyJWTSignature($jwt)) {
			throw new JwtValidatorException ('Unable to verify signature');
		}
	}
	protected function getPossibleJwks() {
		$jwks = $this->additionalJwks;
		$jwksUri = $this->jwksUri;
		if (!$jwksUri) {
			if ( empty($jwks) ) {
				throw new JwtValidatorException ('Unable to verify signature due to no jwksUri being defined');
			} else {
				return $jwks;
			}
		}

		$jwksObject = json_decode($this->fetchURL($jwksUri), false);
		if ($jwks === NULL || !is_object($jwksObject) || empty($jwksObject->keys)) {
			throw new JwtValidatorException('Error decoding JSON from jwksUri');
		}
		return array_merge($jwksObject->keys, $jwks);
	}

	/**
	 * @param object $claims
	 * @param string|null $accessToken
	 * @return bool
	 * @throws JwtValidatorException
	 */
	protected function verifyJWTClaims($claims, string $accessToken = null): bool
	{
		if (!$this->validateIssuer($claims->iss ?? null)) {
			throw new JwtValidatorException("Invalid issuer");
		}
		if (!$this->validateAudience($claims->aud ?? null)) {
                        throw new JwtValidatorException("Invalid audience");
                }
		if( !$this->validateSubject($claims->sub ?? null)) {
                        throw new JwtValidatorException("Invalid subject");
                }
                if (!$this->validateJti($claims->jti ?? null)) {
                        throw new JwtValidatorException("Invalid jti");
                }
                if (!$this->validateIat($claims->iat ?? null)) {
                        throw new JwtValidatorException("Invalid iat");
                }
                if (!$this->validateExp($claims->exp ?? null)) {
                        throw new JwtValidatorException("Invalid exp");
                }
                if (!$this->validateNbf($claims->nbf ?? null)) {
                        throw new JwtValidatorException("Invalid nbf");
                }
		return true;
	}

	protected function validateIssuer($iss): bool {
		if ( $iss === null ) {
			return false;
		}
		if ($this->issuerValidator !== null) {
			return $this->issuerValidator->__invoke($iss);
		}

		return $iss === $this->getIssuer();
	}
	protected function validateIat( $iat ): bool {
		if ( $iat === null ) {
			return !$this->requiresIat();
		}
		return is_int($iat) && ($iat <= time() + $this->leeway) && ($iat >= time() - $this->allowedTokenAge);
	}
	protected function validateExp( $exp ): bool {
		if ( $exp === null ) {
			return false;
		}
		return is_int($exp) && ($exp >= time() - $this->leeway);
	}
	protected function validateNbf( $nbf ): bool {
		if ( $nbf === null ) {
			return false;
		}
		return is_int($nbf) && ($nbf <= time() + $this->leeway);
	}
	abstract protected function validateAudience($aud): bool;
	abstract protected function validateJti($jti): bool;
	abstract protected function validateSubject($sub): bool;
	protected function requiresIat(): bool {
		return false;
	}

	/**
	 * @param string $jwt encoded JWT
	 * @param int $section the section we would like to decode
	 * @return object|string|null
	 */
	protected function decodeJWT(string $jwt, int $section = 0) {
		$parts = explode('.', $jwt);
		return json_decode($this->base64url_decode($parts[$section] ?? ''), false);
	}

	/**
	 * @param string $url
	 * @param string | null $post_body string If this is set the post type will be POST
	 * @param array $headers Extra headers to be sent with the request. Format as 'NameHeader: ValueHeader'
	 * @return bool|string
	 * @throws JwtValidatorException
	 */
	protected function fetchURL(string $url, string $post_body = null, array $headers = []) {
		$ch = curl_init();

		// Determine whether this is a GET or POST
		if ($post_body !== null) {
			// curl_setopt($ch, CURLOPT_POST, 1);
			// Allows to keep the POST method even after redirect
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);

			// Default content type is form encoded
			$content_type = 'application/x-www-form-urlencoded';

			// Determine if this is a JSON payload and add the appropriate content type
			if (is_object(json_decode($post_body, false))) {
				$content_type = 'application/json';
			}

			// Add POST-specific headers
			$headers[] = "Content-Type: $content_type";
		}

		// Set the User-Agent
		curl_setopt($ch, CURLOPT_USERAGENT, $this->getUserAgent());

		// If we set some headers include them
		if(count($headers) > 0) {
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		}

		// Set URL to download
		curl_setopt($ch, CURLOPT_URL, $url);

		if (isset($this->httpProxy)) {
			curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
		}

		// Include header in result? (0 = yes, 1 = no)
		curl_setopt($ch, CURLOPT_HEADER, 0);

		// Allows to follow redirect
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

		// Should cURL return or print out the data? (true = return, false = print)
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		// Timeout in seconds
		curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeOut);

		// Download the given URL, and return output
		$output = curl_exec($ch);

		if ($output === false) {
			throw new JwtValidatorException('Curl error: (' . curl_errno($ch) . ') ' . curl_error($ch));
		}

		// Close the cURL resource, and free system resources
		curl_close($ch);

		return $output;
	}

	/**
	 * @throws JwtValidatorException
	 */
	public function getIssuer(): string
	{
		if (!isset($this->issuer)) {
			throw new JwtValidatorException('The issuer has not been set');
		}

		return $this->issuer;
	}

	/**
	 * Use this for custom issuer validation
	 * The given function should accept the issuer string from the JWT claim as the only argument
	 * and return true if the issuer is valid, otherwise return false
	 */
	public function setIssuerValidator(callable $issuerValidator) {
		$this->issuerValidator = $issuerValidator;
	}

	/**
	 * Set timeout (seconds)
	 *
	 * @param int $timeout
	 */
	public function setTimeout(int $timeout) {
		$this->timeOut = $timeout;
	}

	public function getTimeout(): int
	{
		return $this->timeOut;
	}

	/**
	 * @return callable
	 */
	public function getIssuerValidator() {
		return $this->issuerValidator;
	}


	public function getLeeway(): int
	{
		return $this->leeway;
	}

	public function setCodeChallengeMethod(string $codeChallengeMethod) {
		$this->codeChallengeMethod = $codeChallengeMethod;
	}

	/**
	 * @throws JwtValidatorException
	 */
	protected function verifyJWKHeader($jwk)
	{
		throw new JwtValidatorException('Self signed JWK header is not valid');
	}

	/**
	 * @param string $jwe The JWE to decrypt
	 * @return string the JWT payload
	 * @throws JwtValidatorException
	 */
	protected function handleJweResponse(string $jwe): string
	{
		throw new JwtValidatorException('JWE response is not supported, please extend the class and implement this method');
	}

	/**
	 * A wrapper around base64_decode which decodes Base64URL-encoded data,
	 * which is not the same alphabet as base64.
	 * @param string $base64url
	 * @return bool|string
	 */
	private function base64url_decode(string $base64url) {
		// "Shouldn't" be necessary, but why not
		$padding = strlen($base64url) % 4;
		if ($padding > 0) {
			$base64url .= str_repeat('=', 4 - $padding);
		}
		$base64 = strtr($base64url, '-_', '+/');

		return base64_decode($base64);
	}
	protected function getUserAgent() {
		return "JWT validator";
	}
}
