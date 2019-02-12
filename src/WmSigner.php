<?php

namespace Webmoney;

use function Couchbase\defaultDecoder;

class WmSigner implements SignerInterface
{
    protected $keyExponent;
    protected $keyModulus;

    const MATH_GMP = "gmp";
    const MATH_BCMATH = "bcmath";

    protected static $mathLibrary;

    /**
     * WMSigner constructor.
     * @param $modulus
     * @param $exponent
     * @throws WmException
     */
    public function __construct($modulus, $exponent)
    {
        $this->keyExponent = $exponent;
        $this->keyModulus = $modulus;

        if (!$modulus) {
            throw new WmException("modulus not provided.");
        }

        if (!$exponent) {
            throw new WmException("exponent not provided.");
        }
    }

    public static function setMathLibrary($library) {
        static::$mathLibrary = $library;
    }

    /**
     * @throws WmException
     */
    public static function getMathLibrary() {
        if (!static::$mathLibrary) {
            foreach (["gmp" => self::MATH_GMP, "bcmath" => self::MATH_BCMATH] as $extension => $math) {
                if (extension_loaded($extension)) {
                    static::$mathLibrary = $math;
                    break;
                }
            }
        }

        if (!static::$mathLibrary) {
            throw new WmException("Neither 'gmp' nor 'bcmath' extension loaded");
        }

        return static::$mathLibrary;
    }

    /**
     * @param $xmlKey
     * @return WmSigner
     * @throws WmException
     */
    public static function fromXml($xmlKey)
    {
        $xml = simplexml_load_string($xmlKey);

        $exponent = static::reverseToDecimal(base64_decode((string)$xml->Modulus));
        $modulus = static::reverseToDecimal(base64_decode((string)$xml->D));

        return new WmSigner($modulus, $exponent);
    }

    /**
     * @param $wmid
     * @param $keyFile
     * @param $keyPassword
     * @return WmSigner
     * @throws WmException
     */
    public static function fromKeyFile($wmid, $keyFile, $keyPassword)
    {
        if (!file_exists($keyFile)) {
            throw new WmException('Key file not found: '.$keyFile);
        }

        $keyData = file_get_contents($keyFile);

        if (false === $keyData) {
            throw new WmException('Key file is not readable: '.$keyFile);
        }

        return static::fromKeyData($wmid, $keyData, $keyPassword);
    }

    /**
     * @param $wmid
     * @param $data
     * @param $keyPassword
     * @return WmSigner
     * @throws WmException
     */
    public static function fromKeyData($wmid, $data, $keyPassword)
    {
        if (!$wmid) {
            throw new WmException("wmid not provided.");
        }
        $keyData = Unpacker::create($data)
            ->match("v", 1, "reserved")
            ->match("v", 1, "signflag")
            ->match("a", 16, "checksum")
            ->match("V", 1, "len")
            ->match("a", "*", "buf");

        $buf = static::secureKeyByIDPW($wmid, $keyPassword, $keyData['buf']);

        static::checkKeyData($buf, $keyData['reserved'], $keyData['len'], $keyData['checksum']);

        $unpacked = Unpacker::create($buf)
            ->match("V", 1, "reserved")
            ->match("v", 1, "exp_len")
            ->match("a", "exp_len", "exponent")
            ->match("v", 1, "mod_len")
            ->match("a", "mod_len", "modulus");

        $exponent = static::reverseToDecimal($unpacked["exponent"]);
        $modulus = static::reverseToDecimal($unpacked["modulus"]);

        return new WmSigner($modulus, $exponent);
    }

    /**
     * @param $binaryData
     * @return string
     * @throws WmException
     */
    protected static function reverseToDecimal($binaryData)
    {
        return static::hex2dec(bin2hex(strrev($binaryData)));
    }

    protected static function strlen($data)
    {
        return mb_strlen($data, 'windows-1251');
    }

    /**
     * @param $data
     * @return string
     * @throws WmException
     */
    protected static function md4($data)
    {
        if (function_exists('mhash')) {
            return mhash(MHASH_MD4, $data);
        }
        if (function_exists('hash')) {
            return hash('md4', $data, true);
        }

        throw new WmException("Could not calculate md4 hash - neither hash() nor mhash() function found");
    }


    /**
     * @param $m
     * @param $e
     * @param $n
     * @return string|null
     * @throws WmException
     */
    protected static function bcpowmod($m, $e, $n)
    {
        switch (static::getMathLibrary()) {
            case static::MATH_GMP:
                return gmp_strval(gmp_powm($m, $e, $n));
            case static::MATH_BCMATH:
                return bcpowmod($m, $e, $n);
        }
    }

    /**
     * @param $number
     * @return string
     * @throws WmException
     */
    protected static function dec2hex($number)
    {
        switch (static::getMathLibrary()) {
            case static::MATH_GMP:
                $hex = gmp_strval($number, 16);
                if (static::strlen($hex) % 2) {
                    $hex = '0'.$hex;
                }

                return $hex;
            case static::MATH_BCMATH:
                $hexValues = '0123456789ABCDEF';
                $hex = '';

                while ($number != '0') {
                    $hex = $hexValues[bcmod($number, '16')].$hex;
                    $number = bcdiv($number, '16', 0);
                }

                if (static::strlen($hex) % 2) {
                    $hex = '0'.$hex;
                }

                return $hex;
        }
    }

    /**
     * @param $number
     * @return string
     * @throws WmException
     */
    protected static function hex2dec($number)
    {
        switch (static::getMathLibrary()) {
            case static::MATH_GMP:
                return gmp_strval("0x".$number, 10);
            case static::MATH_BCMATH:
                $decValue = '0';
                $number = strrev(strtoupper($number));
                for ($i = 0; $i < static::strlen($number); $i++) {
                    $n = hexdec($number[$i]);
                    $decValue = bcadd(bcmul(bcpow('16', $i, 0), $n, 0), $decValue, 0);
                }

                return $decValue;
        }
    }

    protected static function shortunswap($hex)
    {
        $result = '';
        while (static::strlen($hex) < 132) {
            $hex = '00'.$hex;
        }
        for ($i = 0; $i < static::strlen($hex) / 4; $i++) {
            $result = substr($hex, $i * 4, 4).$result;
        }
        return $result;
    }

    protected static function xorStr($str, $xor, $shift = 0)
    {
        $strLength = static::strlen($str);
        $xorLength = static::strlen($xor);
        $i = $shift;
        $k = 0;
        while ($i < $strLength) {
            $str[$i] = chr(ord($str[$i]) ^ ord($xor[$k]));
            $i++;
            $k++;
            if ($k >= $xorLength) {
                $k = 0;
            }
        }
        return $str;
    }


    /**
     * @param $wmid
     * @param $pass
     * @param $buf
     * @return mixed
     * @throws WmException
     */
    protected static function secureKeyByIDPW($wmid, $pass, $buf)
    {
        $digest = static::md4($wmid.$pass);
        return static::xorStr($buf, $digest, 6);
    }


    /**
     * @param $buf
     * @param $reserved
     * @param $len
     * @param $checksum
     * @throws WmException
     */
    protected static function checkKeyData($buf, $reserved, $len, $checksum)
    {
        $data = ''
            .pack('v', $reserved)
            .pack('v', 0)
            .pack('V4', 0, 0, 0, 0)
            .pack('V', $len)
            .$buf;

        $digest = static::md4($data);

        if (0 !== strcmp($digest, $checksum)) {
            throw new WmException('Hash check failed. Key data seems to be corrupted.');
        }
    }

    /**
     * @param $data
     * @return string
     * @throws WmException
     */
    public function sign($data)
    {
        $plain = static::md4($data);

        for ($i = 0; $i < 10; ++$i) {
            $plain .= pack('V', mt_rand());
        }

        $plain = pack('v', static::strlen($plain)).$plain;
        $m = static::reverseToDecimal($plain);

        $a = static::bcpowmod($m, $this->keyExponent, $this->keyModulus);

        $result = strtolower($this->shortunswap(static::dec2hex($a)));

        return $result;
    }

    public function getKeyExponent()
    {
        return $this->keyExponent;
    }

    public function getKeyModulus()
    {
        return $this->keyModulus;
    }
}
