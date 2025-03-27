<?php

require_once 'Stage.php';

class Version {
	private int $major;
	private int $minor;
	private int $patch;
	private Stage $stage;
	private int $stageTag;
	private string $version;

	public function __construct(string $version) {
		$components = [];
		if (preg_match('/^(\d+)\.(\d+)\.(\d+)(?:-((alpha|beta|rc|release)(\d*)))?$/iu',
						$version,
						$components) === 1) {
			$this->major = (int) $components[1];
			$this->minor = (int) $components[2];
			$this->patch = (int) $components[3];

			switch (strtolower($components[5] ?? 'release')) {
				case 'alpha':
					$this->stage = Stage::alpha;
					break;
				case 'beta':
					$this->stage = Stage::beta;
					break;
				case 'rc':
					$this->stage = Stage::rc;
					break;
				default:
					$this->stage = Stage::release;
			}

			$this->stageTag = (int) ($components[6] ?? 1);
			$this->version = $this->major . '.' . $this->minor . '.' . $this->patch . '-' . $this->stage->name . $this->stageTag;
		}
	}

	public function isValid(): bool {
		return isset($this->version);
	}

	public function toString(): string {
		return $this->version;
	}

	public function stageName(): string {
		return $this->stage->name;
	}

	public function isOlder(string|Version $version): bool {
		return (!$this->equals($version) && !$this->isNewer($version));
	}

	public function equals(string|Version $version): bool {
		if (is_string($version)) {
			$version = new Version($version);
		}
		return ($this->major() == $version->major() &&
				$this->minor() == $version->minor() &&
				$this->patch() == $version->patch() &&
				$this->stage() == $version->stage() &&
				$this->tag() == $version->tag());
	}

	public function major(): int {
		return $this->major;
	}

	public function minor(): int {
		return $this->minor;
	}

	public function patch(): int {
		return $this->patch;
	}

	public function stage(): Stage {
		return $this->stage;
	}

	public function tag(): int {
		return $this->stageTag;
	}

	public function isNewer(string|Version $version): bool {
		if (is_string($version)) {
			$version = new Version($version);
		}

		if ($this->major() != $version->major()) {
			return $this->major() > $version->major();
		}

		if ($this->minor() != $version->minor()) {
			return $this->minor() > $version->minor();
		}

		if ($this->patch() != $version->patch()) {
			return $this->patch() > $version->patch();
		}

		if ($this->stage() != $version->stage()) {
			return $this->stageValue() > $version->stageValue();
		}

		if ($this->tag() != $version->tag()) {
			return $this->tag() > $version->tag();
		}

		return false;
	}

	public function stageValue(): string {
		return $this->stage->value;
	}
}

?>
