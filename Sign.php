<?php

class Sign
{
    //自己公钥
    private static $publicKeyPath = "";
    //自己私钥
    private static $privateKeyPath = "";
    private static $aesKey;


    private static function publicKeyFormat($pubKey)
    {
        $pubKey = preg_replace("/\s/", "", $pubKey);
        $pubKey = chunk_split($pubKey, 64, "\n");
        $pubKey = "-----BEGIN PUBLIC KEY-----\n$pubKey-----END PUBLIC KEY-----\n";
        return $pubKey;
    }

    private static function privateKeyFormat($priKey)
    {
        $priKey = preg_replace("/\s/", "", $priKey);
        $priKey = chunk_split($priKey, 64, "\n");
        $priKey = "-----BEGIN RSA PRIVATE KEY-----\n$priKey-----END RSA PRIVATE KEY-----\n";
        return $priKey;
    }

    private static function hashCode32($s)
    {
        $h = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $h = self::overflow32(31 * $h + ord($s[$i]));
        }

        return $h;
    }

    private static function overflow32($v)
    {
        $v = $v % 4294967296;
        if ($v > 2147483647) return $v - 4294967296;
        elseif ($v < -2147483648) return $v + 4294967296;
        else return $v;
    }

    private static function randomAESKey($text)
    {
        $sha256 = hash("sha256", $text, true);
        $sha256 = (string)base64_encode($sha256);
        $sha256 = $sha256 . PHP_EOL;
        $hash = abs(self::hashCode32($sha256));
        $sha256 = substr($sha256, 0, 14);
        $integer = 48 + ($hash % 10);
        $ci = chr($integer);
        $chare = 65 + ($hash % 26);
        $cc = chr($chare);
        $key = $ci . $sha256 . $cc;
        return $key;
    }

    //aes加密
    private static function encrypt($str, $keys, $iv)
    {
        $encrypted_string = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $keys, $str, MCRYPT_MODE_CBC, $iv);
        $arr = str_split(base64_encode($encrypted_string), 76);
        $finalString = "";
        foreach ($arr as $value) {
            $finalString .= $value . PHP_EOL;
        }
        return urlencode($finalString);
    }

    //aes解密
    private static function decrypt($str, $keys, $iv)
    {
        $str = urldecode($str);
        $str = str_replace(" ", "+", $str);
        $str = str_replace("\n", "", $str);
        $decrypted_string = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $keys, base64_decode($str), MCRYPT_MODE_CBC, $iv);
        return trim($decrypted_string);
    }
    //公钥加密
    public static function publicEncrypt($data)
    {
        $publicKey = file_get_contents(self::$publicKeyPath);
        $publicKey = self::publicKeyFormat($publicKey);
        $publicKey = openssl_get_publickey($publicKey);
        openssl_public_encrypt($data, $encrypted, $publicKey);
        return base64_encode($encrypted);
    }

    //私钥解密
    private static function privateDecrypt($data)
    {
        $privateKey = file_get_contents(self::$privateKeyPath);
        $privateKey = self::privateKeyFormat($privateKey);
        $privateKey = openssl_get_privatekey($privateKey);
        openssl_private_decrypt($data, $decrypted, $privateKey);
        return $decrypted;
    }

    private static function getAseKey($codeStr)
    {
        $codeStr = base64_decode($codeStr);
        $aseKey = self::privateDecrypt($codeStr);
        return $aseKey;
    }

    //生成签名
    private static function generateSign($data)
    {
        if (self::$privateKeyPath == "") {
            return false;
        }
        $privateKey = file_get_contents(self::$privateKeyPath);
        $privateKey = self::privateKeyFormat($privateKey);
        $privateKey = openssl_get_privatekey($privateKey);
        openssl_sign($data, $sign, $privateKey, OPENSSL_ALGO_SHA256);
        $sign = base64_encode($sign);
        openssl_free_key($privateKey);
        return $sign;
    }

    //验证签名
    private static function checkSign($data, $sign)
    {
        if (self::$publicKeyPath == "") {
            return false;
        }
        $pubKey = file_get_contents(self::$publicKeyPath);
        $pubKey = self::publicKeyFormat($pubKey);
        $pubKey = openssl_get_publickey($pubKey);
        $result = openssl_verify($data, base64_decode($sign), $pubKey, OPENSSL_ALGO_SHA256);
        openssl_free_key($pubKey);
        return $result;
    }


    //使用下面两个函数前先定义公钥和私钥文件路径
    //$publicKeyPath与$privateKeyPath为文件路径
    //公钥和私钥分别为甲方提供的文件夹根目录下的public.key.base64和private.key.base64
    public static function setKeyPath($publicKeyPath, $privateKeyPath)
    {
        self::$privateKeyPath = $privateKeyPath;
        self::$publicKeyPath = $publicKeyPath;
    }

    //加密请求
    public static function sign($json)
    {
        $jsonArr = [];
        //反步骤5
        $aeskey = self::randomAESKey($json);
        //步骤4
        $encryptData = self::encrypt($json, $aeskey, $aeskey);
        //步骤3
        $signStr = self::generateSign($encryptData);
        if (!$signStr) {
            return [];
        }
        $signStr = chunk_split($signStr, 76, PHP_EOL);
        $jsonArr["sign"] = $signStr;
        $jsonArr["data"] = $encryptData;
        //CODE
        $code = self::publicEncrypt($aeskey);
        if (!$code) {
            return [];
        }
        $code = chunk_split($code, 76, PHP_EOL);
        $jsonArr["code"] = $code;
        return json_encode($jsonArr);
    }

    //验证签名
    public static function unsign($json)
    {
        $jsonArr = json_decode($json, true);
        $sd = $jsonArr["data"];
        $sign = $jsonArr["sign"];
        //步骤2
        $checkSign = self::checkSign($sd, $sign);
        if (!$checkSign) {
            return false;
        }
        $code = $jsonArr["code"];
        //步骤3
        self::$aesKey = self::getAseKey($code);
        //步骤4
        $reqDateStr = self::decrypt($sd, self::$aesKey, self::$aesKey);
        //步骤5
        $reqDateStr = self::randomAESKey($reqDateStr);

        if ($reqDateStr == self::$aesKey) {
            return true;
        }
        return false;
    }
}

$json = "{\"business_code\":\"000055\",\"coupen_code\":\"838431010058\",\"customer_no\":\"dgcb\",\"ext\":\"{\\\"money\\\":50000,\\\"tel\\\":\\\"18898800001\\\"}\",\"num\":\"1\",\"order_no\":\"MALL1707201004059622\",\"req_time\":\"2017-07-20 10:05:52\",\"suplier_product_no\":\"provider002\",\"url\":\"http://v2test.ujia007.com/rpc/callback/platform/dgcb/000055\",\"web_url\":\"\"}";
Sign::setKeyPath(dirname(__FILE__)."/public.key.base64",dirname(__FILE__)."/private.key.base64");
$res = Sign::sign($json);
var_dump($res);
