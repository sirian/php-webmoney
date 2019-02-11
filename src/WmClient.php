<?php

namespace Webmoney;

use baibaratsky\WebMoney\Api\X\Request as XRequest;
use baibaratsky\WebMoney\Exception\CoreException;
use baibaratsky\WebMoney\Request\AbstractRequest;
use baibaratsky\WebMoney\Request\AbstractResponse;
use baibaratsky\WebMoney\Request\Requester\CurlRequester;
use baibaratsky\WebMoney\WebMoney;

class WmClient
{
    protected $wmid;
    protected $wmClient;
    protected $signer;

    public function __construct($wmid, SignerInterface $signer)
    {
        $this->wmid = $wmid;
        $this->wmClient = new WebMoney(new CurlRequester());
        $this->signer = new SignerProxy($signer);
    }

    /**
     * @param AbstractRequest $request
     * @return AbstractResponse
     * @throws WmException
     * @throws WmRequestException
     * @throws WmResponseException
     */
    public function send(AbstractRequest $request)
    {
        if ($request instanceof XRequest) {
            $this->signRequest($request);
        }

        $this->validateRequest($request);

        try {
            $response = $this->wmClient->request($request);
        } catch (CoreException $e) {
            throw new WmException($e->getMessage(), $e->getCode(), $e);
        }

        if (0 !== $response->getReturnCode()) {
            throw new WmResponseException($request, $response);
        }

        return $response;
    }

    protected function signRequest(XRequest $request)
    {
        if (!$request->getSignerWmid()) {
            $request->setSignerWmid($this->wmid);
        }

        if (!$request->getSignature()) {
            $request->sign($this->signer);
        }
    }

    /**
     * @param AbstractRequest $request
     * @throws WmRequestException
     */
    protected function validateRequest(AbstractRequest $request)
    {
        if (!$request->validate()) {
            throw new WmRequestException($request);
        }
    }
}
