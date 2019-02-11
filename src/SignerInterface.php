<?php

namespace Webmoney;

interface SignerInterface
{
    public function sign($data);
}
