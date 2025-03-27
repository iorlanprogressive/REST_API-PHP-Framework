<?php

require_once 'Constants.php';
require_once 'User-Agent.php';

class API {
	private static string $ip;
	private static string $requestMethod;
	private static array $headers;
	private static array|string|null $content = null;
	private static UserAgent|null $userAgent = null;
	private static string|null $userIDNAAscii = null;
	private static string|null $userUnicode = null;
	private static bool $headersOnly = false;
	private static array|null $errors = null;

	public static function initialize(): void {
		self::$requestMethod = $_SERVER['REQUEST_METHOD'];
		self::$headersOnly = (self::$requestMethod === 'HEAD');

		if (!setlocale(LC_ALL, 'ru_RU.UTF-8')) {
			self::serverError('Failed to set locale');
		}

		if (!mb_internal_encoding('UTF-8')) {
			self::serverError('Failed to set internal encoding');
		}

		if (!mb_language('uni')) {
			self::serverError('Failed to set language');
		}

		if (!mb_regex_encoding('UTF-8')) {
			self::serverError('Failed to set regex encoding');
		}

		if (!mb_http_output('UTF-8')) {
			self::serverError('Failed to set output encoding');
		}

		if (!ob_start('mb_output_handler')) {
			self::serverError('Failed to enable output buffering');
		}

		if (isset($_SERVER['HTTP_CLIENT_IP'])) {
			self::$ip = self::validIP($_SERVER['HTTP_CLIENT_IP'], null);
		} elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			self::$ip = self::validIP($_SERVER['HTTP_X_FORWARDED_FOR'], null);
		} elseif (isset($_SERVER['REMOTE_ADDR'])) {
			self::$ip = self::validIP($_SERVER['REMOTE_ADDR'], null);
		} else {
			self::forbidden('Failed to determine IP address');
		}

		if (!is_null(BLOCKED_IPS)) {
			self::blockIPs(BLOCKED_IPS, true, true, true, true);
		}

		self::$headers = array_change_key_case(getallheaders());

		if (isset(self::$headers['user-agent'])) {
			self::$userAgent = new UserAgent(self::$headers['user-agent']);
		}

		if (!is_null(USER_AGENT) &&
				self::hasUserAgent() &&
				self::userAgent()->isValid() &&
				strtolower(self::userAgent()->product()) == strtolower(USER_AGENT)) {

			if (!is_null(MIN_SUPPORTED_VERSION) && self::userAgent()->version()->isOlder(MIN_SUPPORTED_VERSION)) {
				self::error([
						'Error' => 'Update required',
						'Current version' => self::userAgent()->version()->toString(),
						'Minimum supported version' => MIN_SUPPORTED_VERSION,
						'Maximum supported version' => MAX_SUPPORTED_VERSION,
						'Latest version' => LATEST_VERSION,
						'Download link' => DOWNLOAD_LINK
				]);
			}

			if (!is_null(MAX_SUPPORTED_VERSION) && self::userAgent()->version()->isNewer(MAX_SUPPORTED_VERSION)) {
				self::error([
						'Error' => 'Unsupported version',
						'Current version' => self::userAgent()->version()->toString(),
						'Minimum supported version' => MIN_SUPPORTED_VERSION,
						'Maximum supported version' => MAX_SUPPORTED_VERSION,
						'Latest version' => LATEST_VERSION,
						'Download link' => DOWNLOAD_LINK
				]);
			}
		}

		if (isset(self::$headers['authorization']) &&
				preg_match('/^Basic\s+[A-Za-z0-9+\/=]+$/i', self::$headers['authorization']) === 1 &&
				isset($_SERVER['PHP_AUTH_USER'])) {

			self::$userIDNAAscii = self::validEmail($_SERVER['PHP_AUTH_USER'], true, null);
			self::$userUnicode = self::validEmail($_SERVER['PHP_AUTH_USER'], false, null);
		}

		if (self::hasContentType()) {
			self::$headers['content-type'] = strtolower(self::$headers['content-type']);

			if (self::$requestMethod === 'PUT' || self::$requestMethod === 'PATCH') {
				$data = file_get_contents('php://input');
				if ($data === false) {
					self::serverError('Failed to get content');
				}

				switch (self::getFullContentType()) {
					case 'application/x-www-form-urlencoded':
						parse_str($data, self::$content);
						break;

					case 'multipart/form-data':
						if (preg_match('/boundary=(.*)$/', self::$headers['content-type'], $boundary) !== 1) {
							self::unsupportedMediaType('Missing or invalid boundary parameter');
						}

						$parts = preg_split("/-+{$boundary[1]}/i", $data, -1, PREG_SPLIT_NO_EMPTY);
						if ($parts === false) {
							self::unsupportedMediaType('Parts are incorrectly separated');
						}

						array_pop($parts);

						foreach ($parts as $part) {
							if (preg_match('/\r\n(.*?)\r\n\r\n/s', $part, $partHeaders) !== 1) {
								self::unsupportedMediaType('Headers are incorrectly separated from content');
							}

							$partHeaders = preg_split('/(\r\n)+/', $partHeaders[1]);
							if ($partHeaders === false) {
								self::unsupportedMediaType('Headers are incorrectly separated');
							}

							$headers = [];
							foreach ($partHeaders as $partHeader) {
								list($header, $value) = explode(':', $partHeader, 2);
								$headers[strtolower(trim($header))] = trim($value);
							}

							if (!isset($headers['content-type'])) {
								self::unsupportedMediaType('Content type not specified');
							}

							if (!isset($headers['content-disposition'])) {
								self::unsupportedMediaType('Content disposition not specified');
							}

							if (preg_match('/(.+);\s*name="([^"]*)"(?:;\s*filename="([^"]*)")?/iu',
											$headers['content-disposition'],
											$disposition) !== 1) {
								self::unsupportedMediaType('Invalid content disposition format');
							}

							if (strtolower($disposition[1]) !== 'form-data') {
								self::unsupportedMediaType('Invalid content disposition type');
							}

							$tempPath = tempnam(sys_get_temp_dir(), 'temp_uploaded_file_');
							if ($tempPath === false) {
								self::serverError('Failed to create temporary upload file');
							}

							$fileData = substr($part, strpos($part, '\r\n\r\n') + 4);
							self::$content[$disposition[2]] = [
									'error' => UPLOAD_ERR_OK,
									'name' => $disposition[3],
									'tmp_name' => $tempPath,
									'size' => strlen($fileData),
									'type' => $headers['content-type']
							];

							if (!file_put_contents($tempPath, $fileData)) {
								self::serverError('Failed to save temporary upload file');
							}
						}
						break;

					default:
						self::$content = $data;
				}
			} elseif (self::$requestMethod === 'POST') {
				switch (self::getFullContentType()) {
					case 'application/x-www-form-urlencoded':
						self::$content = $_POST;
						break;

					case 'multipart/form-data':
						self::$content = $_FILES;
						break;

					default:
						$data = file_get_contents('php://input');
						if ($data === false) {
							self::serverError('Failed to get content');
						}
						self::$content = $data;
				}
			}
		}

		switch (self::$requestMethod) {
			case 'HEAD':
			case 'GET':
				if (function_exists('GET')) {
					GET();
				} else {
					self::success('This API section does not support data retrieval requests (HEAD and GET methods)');
				}
				break;

			case 'POST':
				if (function_exists('POST')) {
					POST();
				} else {
					self::returnAllowedMethods();
				}
				break;

			case 'PUT':
				if (function_exists('PUT')) {
					PUT();
				} else {
					self::returnAllowedMethods();
				}
				break;

			case 'PATCH':
				if (function_exists('PATCH')) {
					PATCH();
				} else {
					self::returnAllowedMethods();
				}
				break;

			case 'DELETE':
				if (function_exists('DELETE')) {
					DELETE();
				} else {
					self::returnAllowedMethods();
				}
				break;

			default:
				self::returnAllowedMethods();
		}

		self::success();
	}

	public static function serverError($message = null): void {
		self::response($message, 500);
	}

	public static function response($message = null, int $code = 200): void {
		if (!self::$headersOnly && !is_null($message)) {
			$message = json_encode($message,
					JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS);

			if ($message === false) {
				http_response_code(500);
				echo 'Failed to convert response to JSON format';
				exit();
			}

			self::contentType('application/json', null, $code);
			echo $message;
		} else {
			http_response_code($code);
		}
		exit();
	}

	public static function contentType(string $type, string|null $subtype = null, int $code = 200): void {
		if (is_null($subtype)) {
			header('content-type: ' . $type);
		} else {
			header('content-type: ' . $type . '/' . $subtype);
		}
		http_response_code($code);
	}

	public static function validIP(string $ip, bool|null $serverError = false): string {
		if (!self::isValidIP($ip)) {
			if (is_null($serverError)) {
				self::forbidden('Invalid IP address');
			}
			if ($serverError === true) {
				self::serverError('Invalid IP address');
			}
			self::registerError('Invalid IP address');
		}
		return $ip;
	}

	public static function isValidIP(string $ip): bool {
		return preg_match('/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/',
						$ip) === 1;
	}

	public static function forbidden($message = null): void {
		self::response($message, 403);
	}

	public static function registerError($message): void {
		if (is_null(self::$errors)) {
			self::$errors = [$message];
		} elseif (!in_array($message, self::$errors)) {
			array_push(self::$errors, $message);
		}
	}

	public static function blockIPs(array|string $rules = PARTIALLY_BLOCKED_IPS,
			bool $rangeStartServerError = true,
			bool $rangeEndServerError = true,
			bool $subnetServerError = true,
			bool|null $maskServerError = true): void {
		if (self::ipMatchesRules($rules, null, $rangeStartServerError, $rangeEndServerError, $subnetServerError, $maskServerError)) {
			self::forbidden('Access denied for this IP address');
		}
	}

	public static function ipMatchesRules(array|string $rules,
			string|null $ip = null,
			bool $ipServerError = false,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null): bool {
		$rules = preg_split('/[\s,;&]+/',
				is_array($rules) ? implode(' ', $rules) : $rules,
				-1,
				PREG_SPLIT_NO_EMPTY);

		if ($rules === false) {
			self::serverError('Failed to classify IP address as matching or not matching the rules');
		}

		$includedRules = [];
		$excludedRules = [];

		foreach ($rules as $rule) {
			$rule = trim($rule);
			if (preg_match('/^[~!^]/', $rule) === 1) {
				array_push($excludedRules, substr($rule, 1));
			} else {
				array_push($includedRules, $rule);
			}
		}

		foreach ($excludedRules as $excludedRule) {
			if (self::ipMatchesRule($excludedRule,
					$ip,
					$ipServerError,
					$rangeStartServerError,
					$rangeEndServerError,
					$subnetServerError,
					$maskServerError)) {
				return false;
			}
		}

		foreach ($includedRules as $includedRule) {
			if (self::ipMatchesRule($includedRule,
					$ip,
					$ipServerError,
					$rangeStartServerError,
					$rangeEndServerError,
					$subnetServerError,
					$maskServerError)) {
				return true;
			}
		}

		return false;
	}

	private static function ipMatchesRule(string $rule,
			string|null $ip = null,
			bool $ipServerError = false,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null): bool {
		if (is_null($ip)) {
			$ip = self::ip();
		}

		if ($rule === '*') {
			return true;
		}

		if (self::isValidIP($rule)) {
			return $ip === $rule;
		}

		if (preg_match('/^(.*?)-(.*)$/', $rule, $rangeBounds) === 1) {
			return self::ipInRange($rangeBounds[1],
					$rangeBounds[2],
					$ip,
					$ipServerError,
					$rangeStartServerError,
					$rangeEndServerError);
		}

		if (strpos($rule, '/') !== false) {
			return self::ipInSubnet($rule,
					$ip,
					$ipServerError,
					$subnetServerError,
					$maskServerError);
		}

		return false;
	}

	public static function ip(): string {
		return self::$ip;
	}

	public static function ipInRange(string $rangeStart,
			string $rangeEnd,
			string|null $ip = null,
			bool $ipServerError = false,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false): bool {
		if (is_null($ip)) {
			$ip = self::ip();
		}

		$ip = ip2long(self::validIP($ip, $ipServerError));
		if ($ip === false) {
			self::serverError('Failed to convert IP address to number');
		}

		$rangeStart = ip2long(self::validIP($rangeStart, $rangeStartServerError));
		if ($rangeStart === false) {
			self::serverError('Failed to convert range start IP address to number');
		}

		$rangeEnd = ip2long(self::validIP($rangeEnd, $rangeEndServerError));
		if ($rangeEnd === false) {
			self::serverError('Failed to convert range end IP address to number');
		}

		return $ip >= $rangeStart && $ip <= $rangeEnd;
	}

	public static function ipInSubnet(string $subnet,
			string|int|null $mask = null,
			string|null $ip = null,
			bool $ipServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null): bool {
		if (is_null($ip)) {
			$ip = self::ip();
		}

		$ip = ip2long(self::validIP($ip, $ipServerError));
		if ($ip === false) {
			self::serverError('Failed to convert IP address to number');
		}

		if (is_null($mask)) {
			list($subnet, $mask) = explode('/', $subnet);
		} elseif (self::isValidSubnetMask($mask)) {
			$mask = self::subnetMaskToCIDR($mask);
		}

		$subnet = ip2long(self::validIP($subnet, $subnetServerError));
		if ($subnet === false) {
			self::serverError('Failed to convert subnet IP address to number');
		}

		$mask = ~((1 << (32 - self::validCIDR($mask,
										is_null($maskServerError) ? $subnetServerError : $maskServerError))) - 1);

		return ($ip & $mask) === ($subnet & $mask);
	}

	public static function isValidSubnetMask(string $mask): bool {
		return preg_match('/^((128|192|224|240|248|252|254)\.0\.0\.0|255\.(0|128|192|224|240|248|252|254)\.0\.0|255\.255\.(0|128|192|224|240|248|252|254)\.0|255\.255\.255\.(0|128|192|224|240|248|252|254|255))$/',
						$mask) === 1;
	}

	public static function subnetMaskToCIDR(string $mask, bool $serverError = false): int {
		$octets = explode('.', self::validSubnetMask($mask, $serverError));
		$binaryString = '';

		foreach ($octets as $octet) {
			$binaryString .= str_pad(decbin($octet), 8, '0', STR_PAD_LEFT);
		}

		return substr_count($binaryString, '1');
	}

	public static function validSubnetMask(string $mask, bool $serverError = false): string {
		if (!self::isValidSubnetMask($mask)) {
			if ($serverError) {
				self::serverError('Invalid subnet mask');
			}
			self::registerError('Invalid subnet mask');
		}
		return $mask;
	}

	public static function validCIDR(string|int $cidr, bool $serverError = false): string|int {
		if (!self::isValidCIDR($cidr)) {
			if ($serverError) {
				self::serverError('Invalid CIDR');
			}
			self::registerError('Invalid CIDR');
		}
		return $cidr;
	}

	public static function isValidCIDR(string|int $cidr): bool {
		if (!is_numeric($cidr)) {
			return false;
		}
		return $cidr >= 0 && $cidr <= 32;
	}

	public static function hasUserAgent(): bool {
		return !is_null(self::userAgent());
	}

	public static function userAgent(): UserAgent|null {
		return self::$userAgent;
	}

	public static function error($message = null): void {
		self::response($message, 400);
	}

	public static function validEmail(string $email,
			bool $punycode = true,
			bool|null $serverError = false,
			bool $forbidden = false): string {
		if (substr_count($email, '@') !== 1) {
			if (is_null($serverError)) {
				if ($forbidden) {
					self::forbidden('Invalid email address');
				}
				self::authError('Invalid email address');
			}
			if ($serverError === true) {
				self::serverError('Invalid email address');
			}
			self::registerError('Invalid email address');
		}

		list($localPart, $domain) = explode('@', $email, 2);

		if (filter_var($localPart . '@' . self::domainToIDNAAscii($domain, $serverError, $forbidden)) === false) {
			if (is_null($serverError)) {
				if ($forbidden) {
					self::forbidden('Invalid email address');
				}
				self::authError('Invalid email address');
			}
			if ($serverError === true) {
				self::serverError('Invalid email address');
			}
			self::registerError('Invalid email address');
		}

		return $localPart .
				'@' .
				($punycode ? self::domainToIDNAAscii($domain, $serverError, $forbidden) : self::domainToUnicode($domain, $serverError, $forbidden));
	}

	public static function authError($message = null): void {
		header('www-authenticate: Basic realm="Account authorization", charset="UTF-8"');
		self::response($message, 401);
	}

	public static function domainToIDNAAscii(string $domain,
			bool|null $serverError = false,
			bool $forbidden = false): string {
		$domain = idn_to_ascii($domain);
		if ($domain === false) {
			if (is_null($serverError)) {
				if ($forbidden) {
					self::forbidden('Invalid domain');
				}
				self::authError('Invalid domain');
			}
			if ($serverError === true) {
				self::serverError('Invalid domain');
			}
			self::registerError('Invalid domain');
		}
		return $domain;
	}

	public static function domainToUnicode(string $domain,
			bool|null $serverError = false,
			bool $forbidden = false): string {
		$domain = idn_to_utf8($domain);
		if ($domain === false) {
			if (is_null($serverError)) {
				if ($forbidden) {
					self::forbidden('Invalid domain');
				}
				self::authError('Invalid domain');
			}
			if ($serverError === true) {
				self::serverError('Invalid domain');
			}
			self::registerError('Invalid domain');
		}
		return $domain;
	}

	public static function hasContentType(): bool {
		return isset(self::$headers['content-type']);
	}

	public static function getFullContentType(): string|null {
		if (!self::hasContentType()) {
			return null;
		}
		return explode(';', self::$headers['content-type'])[0];
	}

	public static function unsupportedMediaType($message = null): void {
		self::response($message, 415);
	}

	public static function success($message = null): void {
		self::response($message, 200);
	}

	private static function returnAllowedMethods(): void {
		$allowedMethods = ['OPTIONS', 'HEAD', 'GET'];

		if (function_exists('POST')) {
			array_push($allowedMethods, 'POST');
		}

		if (function_exists('DELETE')) {
			array_push($allowedMethods, 'DELETE');
		}

		if (function_exists('PUT')) {
			array_push($allowedMethods, 'PUT');
		}

		if (function_exists('PATCH')) {
			array_push($allowedMethods, 'PATCH');
		}

		if (!in_array(self::$requestMethod, $allowedMethods) || self::$requestMethod === 'OPTIONS') {
			header('allow: ' . implode(', ', $allowedMethods));

			if (self::$requestMethod === 'OPTIONS') {
				self::success('Allowed methods: ' . implode(', ', $allowedMethods));
			}

			self::response('The request method ' . self::$requestMethod . ' cannot be applied to this API section',
					405);
		}
	}

	public static function allowIPs(array|string $rules = ALLOWED_IPS,
			bool $rangeStartServerError = true,
			bool $rangeEndServerError = true,
			bool $subnetServerError = true,
			bool|null $maskServerError = true): void {
		if (!self::ipMatchesRules($rules,
				null,
				$rangeStartServerError,
				$rangeEndServerError,
				$subnetServerError,
				$maskServerError)) {
			self::forbidden('Access denied for this IP address');
		}
	}

	public static function processIP(array $handlers): void {
		$done = false;

		foreach ($handlers as $rules => $handler) {
			if (self::ipMatchesRules($rules, null, true, true, true, true) && is_callable($handler)) {
				$handler();
				$done = true;
			}
		}

		if (!$done && isset($handlers[null]) && is_callable($handlers[null])) {
			$handlers[null]();
		}
	}

	public static function safeUser(bool $punycode = true): string|null {
		if (self::hasUser()) {
			return self::safeString(self::user($punycode));
		}
		return null;
	}

	public static function hasUser(): bool {
		return !is_null(self::user());
	}

	public static function user(bool $punycode = true): string|null {
		return $punycode ? self::$userIDNAAscii : self::$userUnicode;
	}

	public static function safeString(string $string): string {
		return urlencode('_' . $string);
	}

	public static function processContentType(array $handlers, bool $required = true): void {
		$done = false;

		foreach ($handlers as $rules => $handler) {
			if (self::contentTypeMatchesRules($rules, $required) && is_callable($handler)) {
				$handler();
				$done = true;
			}
		}

		if (!$done && isset($handlers[null]) && is_callable($handlers[null])) {
			$handlers[null]();
		}
	}

	public static function contentTypeMatchesRules(array|string $rules, bool $required = true): bool {
		$rules = preg_split('/[\s,;&]+(?=(?:[^()]*\([^()]*\))*[^()]*$)/',
				is_array($rules) ? implode(' ', $rules) : $rules,
				-1,
				PREG_SPLIT_NO_EMPTY);

		$includedRules = [];
		$excludedRules = [];

		foreach ($rules as $rule) {
			$rule = trim($rule);
			if (preg_match('/^[~!^]/', $rule) === 1) {
				array_push($excludedRules, substr($rule, 1));
			} else {
				array_push($includedRules, $rule);
			}
		}

		foreach ($excludedRules as $excludedRule) {
			if (self::contentTypeMatchesRule($excludedRule, $required)) {
				return false;
			}
		}

		foreach ($includedRules as $includedRule) {
			if (self::contentTypeMatchesRule($includedRule, $required)) {
				return true;
			}
		}

		return false;
	}

	public static function contentTypeMatchesRule(string $rule, bool $required = true): bool {
		if (!self::hasContentType()) {
			if ($required) {
				self::unsupportedMediaType('Content type not specified');
			}
			return false;
		}

		$type = self::getContentType();
		$subtype = self::contentSubtype();

		if (str_contains($rule, '(')) {
			if (preg_match('/(.+?)\/\((.+)\)/', $rule, $typeAndSubtypes) === 1) {
				list(, $ruleType, $ruleSubtypes) = $typeAndSubtypes;
				$ruleSubtypes = preg_split('/\s*,\s*/', $ruleSubtypes);

				foreach ($ruleSubtypes as $ruleSubtype) {
					if (($ruleType === '*' || $type === $ruleType) && ($ruleSubtype === '*' || $subtype === $ruleSubtype)) {
						return true;
					}
				}
			}
		} else {
			list($ruleType, $ruleSubtype) = explode('/', $rule . '/*');

			if (($ruleType === '*' || $type === $ruleType) && ($ruleSubtype === '*' || $subtype === $ruleSubtype)) {
				return true;
			}
		}

		return false;
	}

	public static function getContentType(): string|null {
		$fullType = self::getFullContentType();
		if (is_null($fullType)) {
			return null;
		}
		return explode('/', $fullType)[0];
	}

	public static function contentSubtype(): string|null {
		$fullType = self::getFullContentType();
		if (is_null($fullType)) {
			return null;
		}
		return explode('/', $fullType)[1];
	}

	public static function filter(string $name, array|null $allowedValues = null) {
		return self::queryParam($name, $allowedValues, false);
	}

	public static function queryParam(string $name,
			array|null $allowedValues = null,
			bool|null $required = true) {
		if ($required !== false && !isset($_GET[$name])) {
			self::registerError('Query parameter "' . $name . '" not provided');
		}

		if ($required && empty($_GET[$name]) && !is_numeric($_GET[$name])) {
			self::registerError('Query parameter "' . $name . '" must have a value');
		}

		if (!is_null($allowedValues) && isset($_GET[$name]) && !in_array($_GET[$name], $allowedValues)) {
			self::registerError('Invalid value for query parameter "' . $name . '"');
		}

		return empty($_GET[$name]) && !is_numeric($_GET[$name]) ? null : $_GET[$name];
	}

	public static function numberFilter(string $name,
			float|null $min = null,
			float|null $max = null) {
		return self::numberQueryParam($name, $min, $max, false);
	}

	public static function numberQueryParam(string $name,
			float|null $min = null,
			float|null $max = null,
			bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}

		if (!is_numeric($value)) {
			self::registerError('Value of query parameter "' . $name . '" must be a number');
		}

		if (!is_null($min) && $value < $min) {
			self::registerError('Value of query parameter "' . $name . '" must be at least ' . $min);
		}

		if (!is_null($max) && $value > $max) {
			self::registerError('Value of query parameter "' . $name . '" must be no more than ' . $max);
		}

		return $value;
	}

	public static function numberFilterMatchingRules(string $name, array|string|int $rules) {
		return self::numberQueryParamMatchingRules($name, $rules, false);
	}

	public static function numberQueryParamMatchingRules(string $name,
			array|string|int $rules,
			bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::numberMatchingRules($value, $rules);
	}

	public static function numberMatchingRules(string|int $number,
			array|string|int $rules,
			bool $serverError = false) {
		if (self::numberMatchesRules($number, $rules, $serverError)) {
			return $number;
		}

		if ($serverError) {
			self::serverError('Number does not match rule');
		}
		self::registerError('Number does not match rule');
	}

	public static function numberMatchesRules(string|int $number,
			array|string|int $rules,
			bool $serverError = false): bool {
		if (!is_numeric($number)) {
			if ($serverError) {
				self::serverError('Invalid number');
			}
			self::registerError('Invalid number');
		}

		if (is_numeric($rules)) {
			return $number == $rules;
		}

		$rules = preg_split('/[\s,;&]+/',
				is_array($rules) ? implode(' ', $rules) : $rules,
				-1,
				PREG_SPLIT_NO_EMPTY);

		$includedRules = [];
		$excludedRules = [];

		foreach ($rules as $rule) {
			$rule = trim($rule);
			$exclude = preg_match('/^[~!^]/', $rule) === 1;

			if ($exclude) {
				$rule = substr($rule, 1);
			}

			if (str_contains($rule, '-')) {
				list($rangeStart, $rangeEnd) = explode('-', $rule);
				$range = range(trim($rangeStart), trim($rangeEnd));
			} else {
				$range = [$rule];
			}

			if ($exclude) {
				$excludedRules = array_merge($excludedRules, $range);
			} else {
				$includedRules = array_merge($includedRules, $range);
			}
		}

		if (in_array($number, $excludedRules)) {
			return false;
		}

		if (in_array($number, $includedRules)) {
			return true;
		}

		return false;
	}

	public static function flagFilter(string $name) {
		return self::flagQueryParam($name, false);
	}

	public static function flagQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}

		if ($value != 0 && $value != 1) {
			self::registerError('Value of query parameter "' . $name . '" must be 0 or 1');
		}

		return $value;
	}

	public static function ipFilter(string $name) {
		return self::ipQueryParam($name, false);
	}

	public static function ipQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validIP($value);
	}

	public static function subnetMaskFilter(string $name) {
		return self::subnetMaskQueryParam($name, false);
	}

	public static function subnetMaskQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validSubnetMask($value);
	}

	public static function cidrFilter(string $name) {
		return self::cidrQueryParam($name, false);
	}

	public static function cidrQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validCIDR($value);
	}

	public static function subnetMaskToCIDRFilter(string $name) {
		return self::subnetMaskToCIDRQueryParam($name, false);
	}

	public static function subnetMaskToCIDRQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::subnetMaskToCIDR($value);
	}

	public static function ipInRangeFilter(string $name,
			string $rangeStart,
			string $rangeEnd,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false) {
		return self::ipInRangeQueryParam($name,
				$rangeStart,
				$rangeEnd,
				false,
				$rangeStartServerError,
				$rangeEndServerError);
	}

	public static function ipInRangeQueryParam(string $name,
			string $rangeStart,
			string $rangeEnd,
			bool|null $required = true,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::requireIPInRange($rangeStart,
				$rangeEnd,
				$value,
				false,
				false,
				$rangeStartServerError,
				$rangeEndServerError);
	}

	public static function requireIPInRange(string $rangeStart,
			string $rangeEnd,
			string|null $ip = null,
			bool $serverError = false,
			bool $ipServerError = false,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false) {
		if (self::ipInRange($rangeStart,
				$rangeEnd,
				$ip,
				$ipServerError,
				$rangeStartServerError,
				$rangeEndServerError)) {
			return $ip;
		}

		if ($serverError) {
			self::serverError('IP address not in range');
		}
		self::registerError('IP address not in range');
	}

	public static function ipInSubnetFilter(string $name,
			string $subnet,
			string|int|null $mask = null,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		return self::ipInSubnetQueryParam($name,
				$subnet,
				$mask,
				false,
				$subnetServerError,
				$maskServerError);
	}

	public static function ipInSubnetQueryParam(string $name,
			string $subnet,
			string|int|null $mask = null,
			bool|null $required = true,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::requireIPInSubnet($subnet,
				$mask,
				$value,
				false,
				false,
				$subnetServerError,
				$maskServerError);
	}

	public static function requireIPInSubnet(string $subnet,
			string|int|null $mask = null,
			string|null $ip = null,
			bool $serverError = false,
			bool $ipServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		if (self::ipInSubnet($subnet,
				$mask,
				$ip,
				$ipServerError,
				$subnetServerError,
				$maskServerError)) {
			return $ip;
		}

		if ($serverError) {
			self::serverError('IP address not in subnet');
		}
		self::registerError('IP address not in subnet');
	}

	public static function ipMatchingRulesFilter(string $name,
			array|string $rules,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		return self::ipMatchingRulesQueryParam($name,
				$rules,
				false,
				$rangeStartServerError,
				$rangeEndServerError,
				$subnetServerError,
				$maskServerError);
	}

	public static function ipMatchingRulesQueryParam(string $name,
			array|string $rules,
			bool $required = true,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::ipMatchingRules($rules,
				$value,
				false,
				false,
				$rangeStartServerError,
				$rangeEndServerError,
				$subnetServerError,
				$maskServerError);
	}

	public static function ipMatchingRules(array|string $rules,
			string|null $ip = null,
			bool $serverError = false,
			bool $ipServerError = false,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		if (self::ipMatchesRules($rules,
				$ip,
				$ipServerError,
				$rangeStartServerError,
				$rangeEndServerError,
				$subnetServerError,
				$maskServerError)) {
			return $ip;
		}

		if ($serverError) {
			self::serverError('IP address does not match rules');
		}
		self::registerError('IP address does not match rules');
	}

	public static function idnaAsciiDomainFilter(string $name) {
		return self::idnaAsciiDomainQueryParam($name, false);
	}

	public static function idnaAsciiDomainQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::domainToIDNAAscii($value, false);
	}

	public static function unicodeDomainFilter(string $name) {
		return self::unicodeDomainQueryParam($name, false);
	}

	public static function unicodeDomainQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::domainToUnicode($value, false);
	}

	public static function emailFilter(string $name, bool $punycode = false) {
		return self::emailQueryParam($name, $punycode, false);
	}

	public static function emailQueryParam(string $name,
			bool $punycode = false,
			bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validEmail($value, $punycode);
	}

	public static function safeFilter(string $name) {
		return self::safeQueryParam($name, false);
	}

	public static function safeQueryParam(string $name, bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::safeString($value);
	}

	public static function safeEmailFilter(string $name, bool $punycode = false) {
		return self::safeEmailQueryParam($name, $punycode, false);
	}

	public static function safeEmailQueryParam(string $name,
			bool $punycode = false,
			bool|null $required = true) {
		$value = self::queryParam($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::safeValidEmail($value, $punycode);
	}

	public static function safeValidEmail(string $email,
			bool $punycode = true,
			bool|null $serverError = false,
			bool $forbidden = false): string {
		return self::safeString(self::validEmail($email, $punycode, $serverError, $forbidden));
	}

	public static function sorting(array|null $sortOptions = null) {
		if (is_null($sortOptions)) {
			return self::queryParam('sorting');
		}

		$allowedValues = [];
		foreach ($sortOptions as $sortOption) {
			array_push($allowedValues, $sortOption . '/', $sortOption . '\\');
		}

		return self::queryParam('sorting', $allowedValues);
	}

	public static function numberParam(string $name,
			float|null $min = null,
			float|null $max = null,
			bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}

		if (!is_numeric($value)) {
			self::registerError('Value of parameter "' . $name . '" must be a number');
		}

		if (!is_null($min) && $value < $min) {
			self::registerError('Value of parameter "' . $name . '" must be at least ' . $min);
		}

		if (!is_null($max) && $value > $max) {
			self::registerError('Value of parameter "' . $name . '" must be no more than ' . $max);
		}

		return $value;
	}

	public static function param(string $name,
			array|null $allowedValues = null,
			bool|null $required = true) {
		if (self::$requestMethod !== 'POST' && self::$requestMethod !== 'PUT' && self::$requestMethod !== 'PATCH') {
			self::serverError('Parameter request is made with a request method that does not support request body');
		}

		if ($required !== false && self::getFullContentType() !== 'application/x-www-form-urlencoded') {
			self::error('Parameters must be provided');
		}

		if ($required !== false && !isset(self::$content[$name])) {
			self::registerError('Parameter "' . $name . '" not provided');
		}

		if ($required && empty(self::$content[$name]) && !is_numeric(self::$content[$name])) {
			self::registerError('Parameter "' . $name . '" must have a value');
		}

		if (!is_null($allowedValues) && isset(self::$content[$name]) && !in_array(self::$content[$name], $allowedValues)) {
			self::registerError('Invalid value for parameter "' . $name . '"');
		}

		return empty(self::$content[$name]) && !is_numeric(self::$content[$name]) ? null : self::$content[$name];
	}

	public static function numberParamMatchingRules(string $name,
			array|string|int $rules,
			bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::numberMatchingRules($value, $rules);
	}

	public static function flagParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}

		if ($value != 0 && $value != 1) {
			self::registerError('Value of parameter "' . $name . '" must be 0 or 1');
		}

		return $value;
	}

	public static function ipParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validIP($value);
	}

	public static function subnetMaskParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validSubnetMask($value);
	}

	public static function cidrParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validCIDR($value);
	}

	public static function subnetMaskToCIDRParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::subnetMaskToCIDR($value);
	}

	public static function ipInRangeParam(string $name,
			string $rangeStart,
			string $rangeEnd,
			bool|null $required = true,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::requireIPInRange($rangeStart,
				$rangeEnd,
				$value,
				false,
				false,
				$rangeStartServerError,
				$rangeEndServerError);
	}

	public static function ipInSubnetParam(string $name,
			string $subnet,
			string|int|null $mask = null,
			bool|null $required = true,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::requireIPInSubnet($subnet,
				$mask,
				$value,
				false,
				false,
				$subnetServerError,
				$maskServerError);
	}

	public static function ipMatchingRulesParam(string $name,
			array|string $rules,
			bool $required = true,
			bool $rangeStartServerError = false,
			bool $rangeEndServerError = false,
			bool $subnetServerError = false,
			bool|null $maskServerError = null) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::ipMatchingRules($rules,
				$value,
				false,
				false,
				$rangeStartServerError,
				$rangeEndServerError,
				$subnetServerError,
				$maskServerError);
	}

	public static function idnaAsciiDomainParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::domainToIDNAAscii($value, false);
	}

	public static function unicodeDomainParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::domainToUnicode($value, false);
	}

	public static function emailParam(string $name,
			bool $punycode = false,
			bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validEmail($value, $punycode);
	}

	public static function safeParam(string $name, bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::safeString($value);
	}

	public static function safeEmailParam(string $name,
			bool $punycode = false,
			bool|null $required = true) {
		$value = self::param($name, null, $required);
		if (is_null($value)) {
			return null;
		}
		return self::validEmail($value, $punycode);
	}

	public static function serviceUnavailable($message = '',
			string|int|null $retryAfter = null): void {
		if (!is_null($retryAfter)) {
			header('retry-after: ' . $retryAfter);
		}
		self::response((is_string($message) && strlen($message) === 0) ? UNAVAILABLE_MESSAGE : $message,
				503);
	}

	public static function execute(string $procedure,
			$params = null,
			bool $auth = false,
			bool|null $ip = null) {
		$result = self::query($procedure, $params, $auth, false, $ip);

		if (!is_null($result)) {
			$result = $result->fetch_row();
			if (is_array($result) && count($result) === 1) {
				return $result[0];
			}
			return $result;
		}
	}

	private static function query(string $procedure,
			$params = null,
			bool $auth = false,
			bool $outputParams = false,
			bool|null $ip = null,
			bool $handleErrors = true): mysqli_result|null {
		if ($outputParams) {
			$count = self::numberQueryParam('count', 1, 100);
			$offset = self::numberQueryParam('offset', 0);

			if (is_null($params)) {
				$params = [$count, $offset];
			} elseif (is_array($params)) {
				$params = array_merge($params, [$count, $offset]);
			} else {
				$params = [$params, $count, $offset];
			}
		} else {
			if (!is_null($params) && !is_array($params)) {
				$params = [$params];
			}
		}

		self::handleErrors();

		if ($auth) {
			if (!self::hasUser()) {
				self::authError('Email address for authorization not provided');
			}

			if (!isset($_SERVER['PHP_AUTH_PW'])) {
				self::authError('Secret for authorization not provided');
			}

			if (is_null($params)) {
				$params = [$_SERVER['PHP_AUTH_PW'], self::user(false)];
			} else {
				$params = array_merge($params, [$_SERVER['PHP_AUTH_PW'], self::user(false)]);
			}
		}

		if (($auth && $ip !== false) || $ip) {
			if (is_null($params)) {
				$params = [self::ip()];
			} else {
				$params = array_merge($params, [self::ip()]);
			}
		}

		$connection = new mysqli(null, 'api', base64_decode('YzZXcGdSLmo5MVhseFoqXw=='));
		if ($connection->connect_error) {
			self::serverError('Failed to establish connection with database management system');
		}

		if (!$connection->set_charset('utf8mb4')) {
			self::serverError('Failed to set encoding for database management system');
		}

		if (!$connection->select_db((!is_null(TESTER_IPS) && self::ipMatchesRules(TESTER_IPS)) ? 'orlan-progressive_orlan-droid_testing'
				: 'orlan-progressive_orlan-droid')) {
			self::serverError('Failed to select required database');
		}

		if (is_null($params)) {
			$result = $connection->execute_query('CALL ' . $procedure . '()');
		} else {
			$result = $connection->execute_query('CALL ' . $procedure . '(' . implode(', ', array_fill(0, count($params), '?')) . ')',
					$params);
		}

		$connection->close();

		if ($result === false) {
			self::serverError('Failed to execute database query');
		}

		if ($result === true) {
			return null;
		}

		return $result;
	}

	public static function handleErrors(): void {
		if (!is_null(self::$errors)) {
			self::error(['Error list' => self::$errors]);
		}
	}

	public static function confirmationCode($result): string|int|null {
		return $result['Confirmation code'] ?? null;
	}

	public static function processRecord(string $procedure,
			array|callable $handler,
			$params = null,
			bool $auth = false,
			bool|null $ip = null,
			bool $trigger = true,
			callable|bool $completion = true): void {
		self::processResult(self::record($procedure, $params, $auth, $ip),
				$handler,
				$trigger,
				$completion);
	}

	public static function processResult($result,
			array|callable $handler,
			bool $trigger = true,
			callable|bool $completion = true): void {
		$eventCode = self::eventCode($result);

		if (is_callable($handler)) {
			if ($trigger) {
				if (intdiv($eventCode, 100) === 2) {
					$handler($result);
				}
			} else {
				if (!self::completedWithError($result)) {
					$handler($result);
				}
			}
		} else {
			if ($trigger) {
				if (isset($handler[$eventCode])) {
					$handler[$eventCode]($result);
				} elseif (isset($handler[$eventCode / 100])) {
					$handler[$eventCode / 100]($result);
				} elseif (isset($handler[null])) {
					$handler[null]($result);
				}
			} else {
				$errorCode = self::errorCode($result);
				if (isset($handler[$errorCode])) {
					$handler[$errorCode]($result);
				} elseif (isset($handler[null])) {
					$handler[null]($result);
				}
			}
		}

		if (is_callable($completion)) {
			$completion();
		}

		if ($completion !== false) {
			self::returnResult($result);
		}
	}

	public static function eventCode($result): string|int {
		return $result['Event code'] ?? 200;
	}

	public static function completedWithError($result,
			string|int|null $error = null): bool {
		$errorCode = self::errorCode($result);
		if (is_null($errorCode)) {
			return false;
		}

		if (is_null($error)) {
			return true;
		}

		return $errorCode == $error;
	}

	public static function errorCode($result): string|int|null {
		return $result['Error code'] ?? null;
	}

	public static function returnResult($result): void {
		if (is_array($result) && isset($result['Event code'])) {
			$eventCode = $result['Event code'];
			unset($result['Event code']);

			if (isset($result['Error code'])) {
				if (!isset(ERRORS[$result['Error code']])) {
					self::serverError('Failed to interpret error code');
				}
				$result = ['Error' => ERRORS[$result['Error code']]] + $result;
			}

			if ($eventCode == 201) {
				if (!isset($result['Location'])) {
					self::serverError('Failed to get created resource location');
				}
				$location = $result['Location'];
				unset($result['Location']);
			}

			if (count($result) === 1) {
				$result = $result[array_key_first($result)];
			} elseif (!count($result)) {
				$result = null;
			}

			switch ($eventCode) {
				case 200:
					self::success($result);
				case 201:
					self::created($location, $result);
				case 202:
					self::accepted($result);
				case 400:
					self::error($result);
				case 401:
					self::authError($result);
				case 403:
					self::forbidden($result);
				case 404:
					self::notFound($result);
				case 410:
					self::deleted($result);
				case 451:
					self::unavailableForLegalReasons($result);
				default:
					self::serverError('Failed to interpret event code');
			}
		}

		self::success($result);
	}

	public static function created(string $location,
			$message = null): void {
		header('location: ' . $location);
		self::response($message, 201);
	}

	public static function accepted($message = null): void {
		self::response($message, 202);
	}

	public static function notFound($message = null): void {
		self::response($message, 404);
	}

	public static function deleted($message = null): void {
		self::response($message, 410);
	}

	public static function unavailableForLegalReasons($message = null): void {
		self::response($message, 451);
	}

	public static function record(string $procedure,
			$params = null,
			bool $auth = false,
			bool|null $ip = null): array|null {
		$result = self::query($procedure, $params, $auth, false, $ip);

		if (is_null($result)) {
			self::serverError('Failed to interpret database query result');
		}

		$result = $result->fetch_assoc();
		if ($result === false) {
			self::serverError('Failed to get record from database query');
		}

		return $result;
	}

	public static function processObject(string $procedure,
			array|callable $handler,
			$params = null,
			bool $auth = false,
			bool|null $ip = null,
			string $class = 'stdClass',
			array $args = [],
			bool $trigger = true,
			callable|bool $completion = true): void {
		self::processResult(self::object($procedure, $params, $auth, $ip, $class, $args),
				$handler,
				$trigger,
				$completion);
	}

	public static function object(string $procedure,
			$params = null,
			bool $auth = false,
			bool|null $ip = null,
			string $class = 'stdClass',
			array $args = []): object|null {
		$result = self::query($procedure, $params, $auth, false, $ip);

		if (is_null($result)) {
			self::serverError('Failed to interpret database query result');
		}

		$result = $result->fetch_object($class, $args);
		if ($result === false) {
			self::serverError('Failed to get object from database query');
		}

		return $result;
	}

	public static function processRecords(string $procedure,
			array|callable $handler,
			$params = null,
			bool $auth = false,
			bool $outputParams = false,
			bool|null $ip = null,
			bool $trigger = true,
			callable|bool $completion = true): void {
		self::processResult(self::records($procedure, $params, $auth, $outputParams, $ip),
				$handler,
				$trigger,
				$completion);
	}

	public static function records(string $procedure,
			$params = null,
			bool $auth = false,
			bool $outputParams = false,
			bool|null $ip = null): array {
		$result = self::query($procedure, $params, $auth, $outputParams, $ip);

		if (is_null($result)) {
			self::serverError('Failed to interpret database query result');
		}

		$result = $result->fetch_all(MYSQLI_ASSOC);
		if (is_array($result) &&
				count($result) === 1 &&
				is_array($result[array_key_first($result)]) &&
				isset($result[array_key_first($result)]['Event code'])) {
			$result = $result[array_key_first($result)];
		}

		return $result;
	}

	public static function processObjects(string $procedure,
			array|callable $handler,
			$params = null,
			bool $auth = false,
			bool $outputParams = false,
			bool|null $ip = null,
			string $class = 'stdClass',
			array $args = [],
			bool $trigger = true,
			callable|bool $completion = true): void {
		self::processResult(self::objects($procedure, $params, $auth, $outputParams, $ip, $class, $args),
				$handler,
				$trigger,
				$completion);
	}

	public static function objects(string $procedure,
			$params = null,
			bool $auth = false,
			bool $outputParams = false,
			bool|null $ip = null,
			string $class = 'stdClass',
			array $args = []): array {
		$result = self::query($procedure, $params, $auth, $outputParams, $ip);

		if (is_null($result)) {
			self::serverError('Failed to interpret database query result');
		}

		$objects = [];
		while (true) {
			$object = $result->fetch_object();
			if ($object === false) {
				self::serverError('Failed to get object from database query');
			}

			if (is_null($object)) {
				break;
			}

			array_push($objects, $object);
		}

		return $objects;
	}

	public static function returnFile(string|null $name,
			array $extension,
			array|string|null $path = null): void {
		self::handleErrors();

		foreach ($extension as $fileExtension => $contentType) {
			$absolutePath = self::fullFilePath($name, $path, $fileExtension);

			if (file_exists($absolutePath)) {
				self::contentType($contentType);

				if (!readfile($absolutePath)) {
					self::serverError('Failed to send file');
				}
				exit();
			}
		}

		self::notFound('File not uploaded');
	}

	private static function fullFilePath(string $name,
			array|string|null $path = null,
			string|null $extension = null,
			string $basePath = INTERNAL_STORAGE): string {
		if (is_null($extension)) {
			return self::fullPath($path, $basePath) . self::safeString($name);
		}

		return self::fullPath($path, $basePath) . self::safeString($name) . '.' . ltrim($extension, '.');
	}

	private static function fullPath(array|string|null $path = null,
			string $basePath = INTERNAL_STORAGE): string {
		if (is_null($path)) {
			return rtrim($basePath, '/') . '/';
		}

		if (is_array($path)) {
			return rtrim($basePath, '/') . '/' . implode('/',
							array_map(fn($pathPart): string => is_string($pathPart)
									? self::safeString($pathPart)
									: implode('/',
											array_map(fn($dir): string => self::safeString($dir),
													explode('/', trim($pathPart, '/')))),
									$path)) . '/';
		}

		return rtrim($basePath, '/') . '/' . implode('/',
						array_map(fn($dir): string => self::safeString($dir),
								explode('/', trim($path, '/')))) . '/';
	}

	public static function uploadFile(string|null $name = null,
			array|string|null $path = null,
			array|null $extension = null,
			string|null $file = null,
			$message = null,
			string|null $location = null,
			bool|null $fileRequired = null,
			callable|bool $completion = true): void {
		self::handleErrors();

		if (self::getFullContentType() === 'application/x-www-form-urlencoded') {
			if ($fileRequired === true) {
				self::unsupportedMediaType('File must be provided');
			}

			if ($fileRequired === false) {
				self::unsupportedMediaType('Content must be provided');
			}

			self::unsupportedMediaType('File or content must be provided');
		}

		if ($fileRequired !== false && self::getFullContentType() === 'multipart/form-data') {
			if (is_null($file)) {
				$files = self::file();
				foreach ($files as $file) {
					self::saveUploadedFile($file, $path, $extension, $name);
				}
			} else {
				self::saveUploadedFile(self::file($file), $path, $extension, $name);
			}
		} elseif ($fileRequired !== true) {
			self::saveUploadedContent($name, $path, $extension);
		} else {
			self::unsupportedMediaType('File must be provided');
		}

		if (is_callable($completion)) {
			$completion();
		}

		if ($completion !== false) {
			if (is_null($location)) {
				self::success($message);
			}
			self::created($location, $message);
		}
	}

	public static function file(string|null $name = null,
			bool $required = true): array|null {
		if (self::$requestMethod !== 'POST' && self::$requestMethod !== 'PUT' && self::$requestMethod !== 'PATCH') {
			self::serverError('File request is made with a request method that does not support request body');
		}

		if ($required) {
			if (self::getFullContentType() !== 'multipart/form-data') {
				self::unsupportedMediaType('File must be provided');
			}

			if (!is_null($name) && !isset(self::$content[$name])) {
				self::error('File "' . $name . '" not provided');
			}
		}

		if (is_null($name)) {
			return self::$content;
		}

		return self::$content[$name] ?? null;
	}

	private static function saveUploadedFile(array $file,
			array|string|null $path = null,
			array|null $extension = null,
			string|null $name = null): void {
		switch ($file['error']) {
			case UPLOAD_ERR_OK:
				break;
			case UPLOAD_ERR_INI_SIZE:
				self::error('File size too large for server upload');
			case UPLOAD_ERR_FORM_SIZE:
				self::error('File size too large');
			case UPLOAD_ERR_PARTIAL:
				self::serverError('File only partially uploaded');
			case UPLOAD_ERR_NO_FILE:
				self::serverError('File was not uploaded');
			case UPLOAD_ERR_NO_TMP_DIR:
				self::serverError('Temporary directory missing');
			case UPLOAD_ERR_CANT_WRITE:
				self::serverError('Failed to write file to disk');
			case UPLOAD_ERR_EXTENSION:
				self::serverError('File upload stopped by extension');
			default:
				self::serverError('Unknown file upload error');
		}

		if (!is_null($name)) {
			$originalExtension = pathinfo($file['name'], PATHINFO_EXTENSION);
			$file['name'] = $name;
		}

		if (!is_null($extension)) {
			if (!isset($file['type'])) {
				self::error('File type not specified');
			}

			if (!isset($extension[$file['type']])) {
				self::error('Unsupported file type');
			}

			if (!is_array($extension[$file['type']])) {
				$extension[$file['type']] = [$extension[$file['type']]];
			}

			if (!in_array(pathinfo($file['name'], PATHINFO_EXTENSION),
					array_map(fn($fileExtension): string => ltrim($fileExtension, '.'),
							$extension[$file['type']]))) {
				$path = self::fullFilePath($file['name'], $path, $extension[$file['type']][0]);
			} else {
				$path = self::fullFilePath($file['name'], $path);
			}
		} else {
			$path = self::fullFilePath($file['name'], $path, $originalExtension ?? null);
		}

		if (!move_uploaded_file($file['tmp_name'], $path)) {
			self::serverError('Failed to upload file');
		}
	}

	private static function saveUploadedContent(string|null $name = null,
			array|string|null $path = null,
			array|null $extension = null): void {
		if (is_null($name)) {
			self::serverError('Attempt to upload content without specifying filename');
		}

		if (!is_null($extension)) {
			self::requireContentType(array_keys($extension));
			$extension = $extension[self::getFullContentType()];
		}

		self::writeToFile(self::content(), $name, $path, $extension);
	}

	public static function requireContentType(array|string $rules): void {
		if (self::hasContentType() && !self::contentTypeMatchesRules($rules)) {
			self::unsupportedMediaType('Invalid content type');
		}
	}

	public static function writeToFile($data,
			string $name,
			array|string|null $path = null,
			string|null $extension = null,
			bool $append = false): void {
		$absolutePath = self::fullFilePath($name, $path, $extension);

		if ($append) {
			$result = file_put_contents($absolutePath, $data, FILE_APPEND);
		} else {
			$result = file_put_contents($absolutePath, $data);
		}

		if ($result === false) {
			self::serverError('Failed to write data to file');
		}
	}

	public static function content(bool $required = true): string|null {
		if (self::$requestMethod !== 'POST' && self::$requestMethod !== 'PUT' && self::$requestMethod !== 'PATCH') {
			self::serverError('Content request is made with a request method that does not support request body');
		}

		if ($required && is_null(self::$content)) {
			self::error('Content must be provided');
		}

		return self::$content;
	}

	public static function copyFileTo(string|null $name,
			array|string|null $sourcePath = null,
			array|string|null $targetPath = null,
			array|string|null $extension = null,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		return self::copyFile($name,
				$name,
				$sourcePath,
				$targetPath,
				$extension,
				$message,
				$location,
				$successCompletion,
				$failureCompletion);
	}

	public static function copyFile(string|null $sourceName,
			string|null $targetName,
			array|string|null $sourcePath = null,
			array|string|null $targetPath = null,
			array|string|null $extension = null,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		self::handleErrors();
		$done = false;

		if (is_array($extension)) {
			foreach ($extension as $fileExtension) {
				$absolutePath = self::fullFilePath($sourceName, $sourcePath, $fileExtension);

				if (file_exists($absolutePath)) {
					if (!copy($absolutePath,
							self::fullFilePath($targetName, $targetPath, $fileExtension))) {
						self::serverError('Failed to copy file');
					}
					$done = true;
				}
			}
		} else {
			$absolutePath = self::fullFilePath($sourceName, $sourcePath, $extension);

			if (file_exists($absolutePath)) {
				if (!copy($absolutePath,
						self::fullFilePath($targetName, $targetPath, $extension))) {
					self::serverError('Failed to copy file');
				}
				$done = true;
			}
		}

		return self::processFileOperationCompletion($done,
				$message,
				$location,
				$successCompletion,
				$failureCompletion);
	}

	private static function processFileOperationCompletion(bool $done,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		if ($done) {
			if (is_callable($successCompletion)) {
				$successCompletion();
			}

			if ($successCompletion !== false) {
				if (is_null($location)) {
					self::success($message);
				}
				self::created($location, $message);
			}
		} else {
			if (is_callable($failureCompletion)) {
				$failureCompletion();
			}

			if ($failureCompletion !== false) {
				self::notFound('File not uploaded');
			}
		}

		return $done;
	}

	public static function copyFileAs(string|null $sourceName,
			string|null $targetName,
			array|string|null $path = null,
			array|string|null $extension = null,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		return self::copyFile($sourceName,
				$targetName,
				$path,
				$path,
				$extension,
				$message,
				$location,
				$successCompletion,
				$failureCompletion);
	}

	public static function moveFileTo(string|null $name,
			array|string|null $sourcePath = null,
			array|string|null $targetPath = null,
			array|string|null $extension = null,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		return self::moveFile($name,
				$name,
				$sourcePath,
				$targetPath,
				$extension,
				$message,
				$location,
				$successCompletion,
				$failureCompletion);
	}

	public static function moveFile(string|null $sourceName,
			string|null $targetName,
			array|string|null $sourcePath = null,
			array|string|null $targetPath = null,
			array|string|null $extension = null,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		self::handleErrors();
		$done = false;

		if (is_array($extension)) {
			foreach ($extension as $fileExtension) {
				$absolutePath = self::fullFilePath($sourceName, $sourcePath, $fileExtension);

				if (file_exists($absolutePath)) {
					if (!rename($absolutePath,
							self::fullFilePath($targetName, $targetPath, $fileExtension))) {
						self::serverError('Failed to move file');
					}
					$done = true;
				}
			}
		} else {
			$absolutePath = self::fullFilePath($sourceName, $sourcePath, $extension);

			if (file_exists($absolutePath)) {
				if (!rename($absolutePath,
						self::fullFilePath($targetName, $targetPath, $extension))) {
					self::serverError('Failed to move file');
				}
				$done = true;
			}
		}

		return self::processFileOperationCompletion($done,
				$message,
				$location,
				$successCompletion,
				$failureCompletion);
	}

	public static function renameFile(string|null $sourceName,
			string|null $targetName,
			array|string|null $path = null,
			array|string|null $extension = null,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		return self::moveFile($sourceName,
				$targetName,
				$path,
				$path,
				$extension,
				$message,
				$location,
				$successCompletion,
				$failureCompletion);
	}

	public static function deleteFile(string|null $name,
			array|string|null $path = null,
			array|string|null $extension = null,
			$message = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		self::handleErrors();
		$done = false;

		if (is_array($extension)) {
			foreach ($extension as $fileExtension) {
				$absolutePath = self::fullFilePath($name, $path, $fileExtension);

				if (file_exists($absolutePath)) {
					if (!unlink($absolutePath)) {
						self::serverError('Failed to delete file');
					}
					$done = true;
				}
			}
		} else {
			$absolutePath = self::fullFilePath($name, $path, $extension);

			if (file_exists($absolutePath)) {
				if (!unlink($absolutePath)) {
					self::serverError('Failed to delete file');
				}
				$done = true;
			}
		}

		return self::processFileOperationCompletion($done,
				$message,
				null,
				$successCompletion,
				$failureCompletion);
	}

	public static function createDirectory(array|string $path,
			int $permissions = 0775,
			bool $recursive = true,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		self::handleErrors();
		$done = false;

		$absolutePath = self::fullPath($path);

		if (!file_exists($absolutePath)) {
			if (!mkdir($absolutePath, $permissions, $recursive)) {
				self::serverError('Failed to create directory');
			}
			$done = true;
		}

		return self::processFileOperationCompletion($done,
				$message,
				$location,
				$successCompletion,
				$failureCompletion);
	}

	public static function deleteDirectory(array|string $path,
			$message = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true): bool {
		self::handleErrors();
		$done = false;

		$absolutePath = self::fullPath($path);

		if (file_exists($absolutePath)) {
			if (!rmdir($absolutePath)) {
				self::serverError('Failed to delete directory');
			}
			$done = true;
		}

		return self::processFileOperationCompletion($done,
				$message,
				null,
				$successCompletion,
				$failureCompletion);
	}

	public static function requireFile(string $name,
			array|string|null $path = null,
			array|string|null $extension = null,
			bool $serverError = false): void {
		if (!self::fileExists($name, $path, $extension)) {
			if ($serverError) {
				self::serverError('File does not exist');
			}
			self::error('File not uploaded');
		}
	}

	public static function fileExists(string $name,
			array|string|null $path = null,
			array|string|null $extension = null): bool {
		if (is_array($extension)) {
			foreach ($extension as $fileExtension) {
				if (file_exists(self::fullFilePath($name, $path, $fileExtension))) {
					return true;
				}
			}
			return false;
		} else {
			return file_exists(self::fullFilePath($name, $path, $extension));
		}
	}

	public static function unserializeFromFile(string $name,
			array|string|null $path = null,
			string|null $extension = null,
			bool $object = false) {
		return json_decode(self::readFromFile($name, $path, $extension),
				!$object);
	}

	public static function readFromFile(string $name,
			array|string|null $path = null,
			string|null $extension = null,
			int $offset = 0,
			int|null $length = null): string {
		$absolutePath = self::fullFilePath($name, $path, $extension);

		if (!file_exists($absolutePath)) {
			self::serverError('File does not exist');
		}

		$data = file_get_contents($absolutePath, false, null, $offset, $length);
		if ($data === false) {
			self::serverError('Failed to read data from file');
		}

		return $data;
	}

	public static function serializeToFile($data,
			string $name,
			array|string|null $path = null,
			string|null $extension = null): void {
		$data = json_encode($data,
				JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS | JSON_PRETTY_PRINT);

		if ($data === false) {
			self::serverError('Failed to convert data to JSON format for file writing');
		}

		self::writeToFile($data, $name, $path, $extension);
	}

	public static function executeScript(string $scriptName,
			array|string|null $args = null,
			bool $async = false,
			string|bool $log = false,
			bool $redirectErrorStream = false,
			string|null $contentType = null,
			string|null $contentSubtype = null,
			$message = null,
			string|null $location = null,
			array|int|bool $completion = true,
			bool $invertCompletion = false,
			array|int|bool $display = false,
			bool $invertDisplay = false,
			array|callable|null $handlers = null,
			bool $serverError = true) {
		self::handleErrors();

		$command = self::fullFilePath($scriptName, null, 'sh', SCRIPTS_DIRECTORY);

		if (is_string($args)) {
			$command .= ' ' . escapeshellarg($args);
		} elseif (is_array($command)) {
			foreach ($args as $arg => $value) {
				if (is_int($arg)) {
					$command .= ' ' . escapeshellarg($value);
				} elseif (is_string($arg) && preg_match('/^[a-zA-Z0-9_-]+$/iu', $arg) === 1) {
					if (strlen($arg) === 1 && preg_match('/^[a-zA-Z0-9]$/iu', $arg) === 1) {
						$command .= ' -' . $arg . ' ' . escapeshellarg($value);
					} else {
						$command .= ' --' . $arg . ' ' . escapeshellarg($value);
					}
				}
			}
		}

		if ($log !== false) {
			if ($log === true) {
				$log = $scriptName;
			}
			$command .= ' > ' . self::fullFilePath($log, null, 'log', LOGS_DIRECTORY);
		}

		if ($redirectErrorStream) {
			$command .= ' 2>&1';
		}

		if ($async) {
			$command .= ' &';
		}

		$command = escapeshellcmd($command);

		if (!is_null($contentType)) {
			self::contentType($contentType, $contentSubtype);
		}

		if ($async) {
			if (exec($command) === false) {
				self::serverError('Failed to execute external script');
			}

			if (is_callable($handlers)) {
				$handlers();
			}

			if ($completion === true) {
				self::accepted($message);
			}
		} else {
			if (is_null($contentType)) {
				$output = [];
				$result = 0;

				if (exec($command, $output, $result) === false) {
					self::serverError('Failed to execute external script');
				}

				array_unshift($output, $result);

				if (is_callable($handlers)) {
					$handlers();
				}

				if (is_array($handlers)) {
					$done = false;

					foreach ($handlers as $rules => $handler) {
						if (self::numberMatchesRules($result, $rules, $serverError)) {
							$handler($output);
							$done = true;
						}
					}

					if (!$done && isset($handlers[null])) {
						$handlers[null]($output);
					}
				}

				if ($completion === true ||
						(is_int($completion) && ($invertCompletion ? ($result !== $completion) : ($result === $completion))) ||
						(is_array($completion) && in_array($result, $completion) !== $invertCompletion)) {
					if ($display === true ||
							(is_int($display) && ($invertDisplay ? ($result !== $display) : ($result === $display))) ||
							(is_array($display) && in_array($result, $display) !== $invertDisplay)) {
						array_shift($output);

						if ($result !== 0) {
							self::serverError($output);
						}

						if (is_null($location)) {
							self::success($output);
						}
						self::created($location, $output);
					} else {
						if ($result !== 0) {
							self::serverError('External script completed incorrectly');
						}

						if (is_null($location)) {
							self::success($message);
						}
						self::created($location, $message);
					}
				}

				return $output;
			} else {
				$result = 0;

				if (passthru($command, $result) === false) {
					self::serverError('Failed to execute external script');
				}

				if (is_callable($handlers)) {
					$handlers($result);
				}

				if (is_array($handlers)) {
					$done = false;

					foreach ($handlers as $rules => $handler) {
						if (self::numberMatchesRules($result, $rules, $serverError)) {
							$handler($result);
							$done = true;
						}
					}

					if (!$done && isset($handlers[null])) {
						$handlers[null]($result);
					}
				}

				if ($completion === true ||
						(is_int($completion) && ($invertCompletion ? ($result !== $completion) : ($result === $completion))) ||
						(is_array($completion) && in_array($result, $completion) !== $invertCompletion)) {
					if ($result !== 0) {
						self::serverError('External script completed incorrectly');
					}
					exit();
				}

				return $result;
			}
		}
	}

	public static function sendEmail(string $subject,
			string $content,
			$message = null,
			string|null $location = null,
			callable|bool $successCompletion = true,
			callable|bool $failureCompletion = true,
			array|string|null $to = null,
			string|null $unsubscribe = null,
			bool $html = true,
			string|null $from = EMAIL_FROM,
			string $fromAddress = EMAIL_FROM_ADDRESS,
			string|null $domain = EMAIL_DOMAIN,
			bool $toServerError = true,
			bool $fromServerError = true): bool {
		if (is_null($to)) {
			$to = self::user();
		} else {
			if (is_string($to) && str_contains($to, ',')) {
				$to = array_map(fn($recipient) => trim($recipient),
						explode(',', $to));
			}

			if (is_array($to)) {
				$to = implode(', ',
						array_map(fn($recipient) => self::validEmail($recipient, true, $toServerError),
								$to));
			}
		}

		if (!is_null($domain)) {
			$fromAddress .= '@' . $domain;
		}

		$fromAddress = self::validEmail($fromAddress, true, $fromServerError);

		if (is_null($from)) {
			$from = $fromAddress;
		} else {
			$from = self::emailHeader($from) . ' <' . $fromAddress . '>';
		}

		$subject = self::emailHeader($subject);
		$headers = ['From' => $from, 'Return-Path' => $from];

		if ($html) {
			$headers = array_merge($headers, ['MIME-Version' => '1.0', 'Content-Type' => 'text/html; charset=UTF-8']);
		} else {
			$content = wordwrap($content, 70, '\r\n');
		}

		if (!is_null($unsubscribe)) {
			$headers = array_merge($headers, ['List-Unsubscribe' => self::emailHeader($unsubscribe)]);
		}

		self::handleErrors();

		$done = mail($to, $subject, $content, $headers);

		if ($done) {
			if (is_callable($successCompletion)) {
				$successCompletion();
			}

			if ($successCompletion !== false) {
				if (is_null($location)) {
					self::success($message);
				}
				self::created($location, $message);
			}
		} else {
			if (is_callable($failureCompletion)) {
				$failureCompletion();
			}

			if ($failureCompletion !== false) {
				self::serverError('Failed to send email');
			}
		}

		return $done;
	}

	private static function emailHeader(string $header): string {
		return '=?UTF-8?B?' . base64_encode($header) . '?=';
	}
}

API::initialize();

?>
