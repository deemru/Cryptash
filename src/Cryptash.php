<?php

namespace deemru;

class Cryptash
{
    private $psw;
    private $hash;
    private $ivsz;
    private $cbcsz;
    private $macsz;

    /**
     * Creates Cryptash instance
     *
     * @param  string $psw Password string as a secret
     * @param  int $ivsz Size of initialization vector
     * @param  int $macsz Size of message authentication code
     * @param  string $hash Hash type to use
     */
    public function __construct( $psw, $ivsz = 4, $macsz = 4, $hash = 'sha256' )
    {
        $this->psw = $psw;
        $this->hash = $hash;
        $this->ivsz = max( 0, $ivsz );
        switch( $hash )
        {
            case 'sha256': $this->cbcsz = 32; break;
            case 'sha512': $this->cbcsz = 64; break;
            default: $this->cbcsz = strlen( hash( $this->hash, '', true ) );
        }
        $this->macsz = min( $macsz, $this->cbcsz );
    }

    /**
     * Hash based encryption with internal IV and MAC
     *
     * @param  string $data Plaintext data
     *
     * @return string Encrypted data
     */
    public function encryptash( $data )
    {
        if( $this->ivsz )
        {
            $iv = self::rnd( $this->ivsz );
            $data = self::rnd( $this->ivsz ) . $data;
        }
        else
            $iv = '';

        $key = hash( $this->hash, $iv . $this->psw, true );

        if( $this->macsz )
            $iv .= substr( hash( $this->hash, $data . $key, true ), 0, $this->macsz );

        return $iv . $this->cbc( $iv, $key, $data, true );
    }

    /**
     * Hash based decryption with MAC verification
     *
     * @param  string $data Encrypted data
     *
     * @return string Verified plaintext data
     */
    public function decryptash( $data )
    {
        if( strlen( $data ) < 2 * $this->ivsz + $this->macsz )
            return false;

        $key = hash( $this->hash, substr( $data, 0, $this->ivsz ) . $this->psw, true );
        if( $this->macsz )
            $mac = substr( $data, $this->ivsz, $this->macsz );
        $data = $this->cbc( substr( $data, 0, $this->ivsz + $this->macsz ), $key, substr( $data, $this->macsz + $this->ivsz ), false );

        if( $this->macsz && $mac !== substr( hash( $this->hash, $data . $key, true ), 0, $this->macsz ) )
            return false;

        if( strlen( $data ) === $this->ivsz )
            return '';

        return substr( $data, $this->ivsz );
    }

    /**
     * Generates random bytes
     *
     * @param  int $size
     *
     * @return string
     */
    public static function rnd( $size = 8 )
    {
        if( $size === 0 )
            return '';

        static $rndfn;
        if( !isset( $rndfn ) )
        {
            if( function_exists( 'random_bytes' ) )
                $rndfn = 'random_bytes';
            else
            if( function_exists( 'openssl_random_pseudo_bytes' ) )
                $rndfn = 'openssl_random_pseudo_bytes';
            else
            if( function_exists( 'mcrypt_create_iv' ) )
                $rndfn = 'mcrypt_create_iv';
            else
                throw new \Exception( 'No secure random source available' );
        }

        return $rndfn( $size );
    }

    private function cbc( $v, $k, $d, $e )
    {
        $n = strlen( $d );
        if( $n === 0 )
            return '';

        $s = $this->cbcsz;
        $k = hash( $this->hash, $v . $k, true );
        $o = '';

        for( $i = 0;; )
        {
            $l = min( $s, $n - $i );
            $o .= substr( $d, $i, $l ) ^ substr( $k, 0, $l );

            $i += $l;
            if( $i >= $n )
                break;

            $k = hash( $this->hash, substr( $e ? $o : $d, $i - $s, $s ) . $k, true );
        }

        return $o;
    }
}
