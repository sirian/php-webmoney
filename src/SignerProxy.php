<?php

namespace Webmoney;

use baibaratsky\WebMoney\Signer;

class SignerProxy extends Signer implements SignerInterface
{
    protected $signer;

    /**
     * SignerProxy constructor.
     * @param SignerInterface $signer
     */
    public function __construct(SignerInterface $signer)
    {
        $this->signer = $signer;
    }

    public function sign($data)
    {
        return $this->signer->sign($data);
    }

    public function getSigner()
    {
        return $this->signer;
    }
}
