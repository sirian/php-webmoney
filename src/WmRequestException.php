<?php

namespace Webmoney;

use baibaratsky\WebMoney\Request\AbstractRequest;

class WmRequestException extends WmException
{
    protected $request;

    public function __construct(AbstractRequest $request)
    {
        $this->request = $request;
        parent::__construct(json_encode($request->getErrors()));
    }

}
