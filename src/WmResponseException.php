<?php

namespace Webmoney;

use baibaratsky\WebMoney\Request\AbstractRequest;
use baibaratsky\WebMoney\Request\AbstractResponse;

class WmResponseException extends WmException
{
    protected $request;
    protected $response;

    public function __construct(AbstractRequest $request, AbstractResponse $response)
    {
        $this->request = $request;
        $this->response = $response;
        parent::__construct($response->getReturnDescription(), $response->getReturnCode());
    }
}
