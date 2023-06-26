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
        $this->cbcsz = strlen( hash( $this->hash, '', true ) );
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
            $iv = $this->rnd( $this->ivsz );
            $data = $this->rnd( $this->ivsz ) . $data;
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
    static public function rnd( $size = 8 )
    {
        static $rndfn;

        if( $size === 0 )
            return '';

        if( !isset( $rndfn ) )
        {
            if( function_exists( 'random_bytes' ) )
                $rndfn = 2;
            else if( function_exists( 'mcrypt_create_iv' ) )
                $rndfn = 1;
            else
                $rndfn = 0;
        }
        
        if( $rndfn === 2 )
            return random_bytes( $size );
        if( $rndfn === 1 )
            return mcrypt_create_iv( $size );

        $rnd = '';
        while( $size-- )
            $rnd .= chr( mt_rand() );
        return $rnd;
    }

    private function cbc( $v, $k, $d, $e )
    {
        $n = strlen( $d );
        if( $n === 0 )
            return '';

        $s = $this->cbcsz;
        $k = hash( $this->hash, $v . $k, true );
        $o = $d;

        for( $i = 0, $j = 0; $i < $n; ++$i, ++$j )
        {
            if( $j === $s )
            {
                $k = hash( $this->hash, substr( $e ? $o : $d, $i - $s, $s ) . $k, true );
                $j = 0;
            }

            $o[$i] = $d[$i] ^ $k[$j];
        }

        return $o;
    }
}
