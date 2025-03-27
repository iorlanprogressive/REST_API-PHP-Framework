<?php

require_once 'Version.php';

class UserAgent {
	private string $product;
	private Version $version;
	private string $userAgentWithoutInfo;
	private array|null $infoArray = null;
	private string|null $infoString = null;
	private string $userAgent;

	public function __construct(string $userAgent) {
		$components = [];
		if (preg_match('/^((\S+)\/((\d+)\.(\d+)\.(\d+)(?:-((alpha|beta|rc|release)(\d*)))?))(?:\s*\(([^)]+)\))?$/iu',
						$userAgent,
						$components) === 1) {
			$this->product = $components[2];
			$this->version = new Version($components[3]);
			$this->userAgentWithoutInfo = $this->product . '/' . $this->version->toString();
			$this->userAgent = $this->userAgentWithoutInfo;

			if (isset($components[10])) {
				$this->infoArray = array_map(fn($component) => trim($component),
						explode(';', $components[10]));
				$this->infoString = implode('; ', $this->infoArray);
				$this->userAgent .= ' (' . $this->infoString . ')';
			}
		}
	}

	public function toString(): string {
		return $this->userAgent;
	}

	public function isValid(): bool {
		return isset($this->userAgent);
	}

	public function toStringWithoutInfo(): string {
		return $this->userAgentWithoutInfo;
	}

	public function product(): string {
		return $this->product;
	}

	public function version(): Version {
		return $this->version;
	}

	public function infoAsString(): string|null {
		return $this->infoString;
	}

	public function infoContains($value): bool {
		return $this->hasInfo() && in_array($value, $this->info());
	}

	public function hasInfo(): bool {
		return !is_null($this->infoArray);
	}

	public function info(): array|null {
		return $this->infoArray;
	}
}

?>
