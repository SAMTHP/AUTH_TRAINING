<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;


class CheckBrowser
{
    private $browserToken;

    private $browserStatus;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getBrowserToken(): ?string
    {
        return $this->browserToken;
    }

    public function setBrowserToken(string $browserToken): self
    {
        $this->browserToken = $browserToken;

        return $this;
    }

    public function getBrowserStatus(): ?bool
    {
        return $this->browserStatus;
    }

    public function setBrowserStatus(bool $browserStatus): self
    {
        $this->browserStatus = $browserStatus;

        return $this;
    }
}
