<?php

namespace Webmoney;

class Unpacker implements \ArrayAccess
{
    protected $formatParts = [];
    protected $result = [];
    protected $buffer;

    public function __construct($buffer)
    {
        $this->buffer = $buffer;
    }

    public static function create($buffer)
    {
        return new Unpacker($buffer);
    }

    public function match($type, $repeat = "", $name = "")
    {
        $repeat = (string)$repeat;
        $name = (string)$name;

        if (!$this->isValidRepeat($repeat)) {
            if (isset($this->result[$repeat])) {
                $repeat = $this->result[$repeat];
            }
        }
        if ("1" === $repeat) {
            $repeat = "";
        }

        $this->formatParts[] = $type.$repeat.$name;

        $this->result = unpack($this->getFormat(), $this->buffer);

        return $this;
    }

    public function getFormat()
    {
        return implode("/", $this->formatParts);
    }

    public function getResult()
    {
        return $this->result;
    }

    public function offsetExists($offset)
    {
        return isset($this->result, $offset);
    }

    public function offsetGet($offset)
    {
        if (!$this->offsetExists($offset)) {
            throw new \InvalidArgumentException(sprintf(
                "Key %s does not exist. Available: %s",
                $offset,
                implode(", ", array_keys($this->result))
            ));
        }
        return $this->result[$offset];
    }


    public function offsetSet($offset, $value)
    {
        $this->result[$offset] = $value;
        return $this;
    }


    public function offsetUnset($offset)
    {
        unset($this->result, $offset);
        return $this;
    }

    protected function isValidRepeat($repeat)
    {
        return "" === $repeat || "*" === $repeat || "@" === $repeat || ctype_digit($repeat);
    }
}
