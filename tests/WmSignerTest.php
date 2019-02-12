<?php
/** @noinspection PhpDocMissingThrowsInspection */

/** @noinspection PhpUnhandledExceptionInspection */

namespace Webmoney;

use PHPUnit\Framework\TestCase;

function file_get_contents($filename)
{
    if (WmSignerTest::$mockFileGetContents) {
        return false;
    }
    return \file_get_contents($filename);
}


class WmSignerTest extends TestCase
{
    const TEST_STRING = 'TEST';
    const TEST_SIGNATURE = '7ac427edcfb26b26ee0599ba8e47fece628d0b1cefe18225e5a2136fddce6aa0d8390120877735b175291596eedf0bf6304cb5338772b2331e5833e5404ec10d0504';
    const ANOTHER_TEST_STRING = 'another test';

    const WMID = '405002833238';
    const KEY_PASSWORD = 'FvGqPdAy8reVWw789';
    const KEY_FILE = __DIR__."/test.kwm";

    public static $mockFileGetContents = false;

    public function mathLibraries()
    {
        return [
            [WmSigner::MATH_GMP],
            [WmSigner::MATH_BCMATH],
        ];
    }

    /**
     * @param $mathLibrary
     * @dataProvider mathLibraries
     */
    public function testSign($mathLibrary)
    {
        WmSigner::setMathLibrary($mathLibrary);

        $signer = WmSigner::fromKeyFile(self::WMID, self::KEY_FILE, self::KEY_PASSWORD);

        $this->assertNotEquals(
            $signer->sign(self::TEST_STRING),
            $signer->sign(self::TEST_STRING)
        );

        $this->assertEquals(self::TEST_SIGNATURE, $this->seededSignature($signer, self::TEST_STRING));
        $this->assertNotEquals(self::TEST_SIGNATURE, $signer->sign(self::ANOTHER_TEST_STRING));
        $this->assertEquals(self::TEST_SIGNATURE, $this->seededSignature($signer, self::TEST_STRING));
    }

    public function testKeyData()
    {
        $keyData = file_get_contents(self::KEY_FILE);
        $signer = WmSigner::fromKeyData(self::WMID, $keyData, self::KEY_PASSWORD);
        $seededSignatureStringKey = $this->seededSignature($signer, self::TEST_STRING);
        $this->assertEquals(self::TEST_SIGNATURE, $seededSignatureStringKey);
    }

    public function testWmidException()
    {
        $this->expectExceptionObject(new WmException("wmid not provided."));
        WmSigner::fromKeyData('', '', '');
    }

    public function testKeyFileNotFoundException()
    {
        $noSuchFile = 'no_such_file';
        $this->expectExceptionObject(new WmException('Key file not found: '.$noSuchFile));
        WmSigner::fromKeyFile(self::WMID, $noSuchFile, '');
    }

    public function testKeyFileReadingException()
    {
        $this->expectExceptionObject(new WmException('Key file is not readable: '.self::KEY_FILE));
        self::$mockFileGetContents = true;
        try {
            WmSigner::fromKeyFile(self::WMID, self::KEY_FILE, self::KEY_PASSWORD);
        } finally {
            self::$mockFileGetContents = false;
        }
    }

    public function testKeyFileCorruptedException()
    {
        $this->expectExceptionObject(new WmException('Hash check failed. Key data seems to be corrupted.'));
        WmSigner::fromKeyFile(self::WMID, self::KEY_FILE, '');
    }

    protected function seededSignature(SignerInterface $signer, $data)
    {
        mt_srand(0);
        return $signer->sign($data);
    }

    protected function createSigner()
    {
        return WmSigner::fromKeyFile(self::WMID, self::KEY_FILE, self::KEY_PASSWORD);
    }
}
