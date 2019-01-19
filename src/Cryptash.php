<?php

namespace deemru;

class Cryptash
{
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
        $this->cbcsz = strlen( self::hash( '' ) );
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

        $key = self::hash( $iv . $this->psw );

        if( $this->macsz )
            $iv .= substr( self::hash( $data . $key ), 0, $this->macsz );

        return $iv . self::cbc( $iv, $key, $data, true );
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

        $key = self::hash( substr( $data, 0, $this->ivsz ) . $this->psw );
        if( $this->macsz )
            $mac = substr( $data, $this->ivsz, $this->macsz );
        $data = self::cbc( substr( $data, 0, $this->ivsz + $this->macsz ),
                           $key, substr( $data, $this->macsz + $this->ivsz ) );

        if( $this->macsz && $mac !== substr( self::hash( $data . $key ), 0, $this->macsz ) )
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

    private function hash( $data )
    {
        return hash( $this->hash, $data, true );
    }

    private function cbc( $v, $k, $d, $e = false )
    {
        $s = $this->cbcsz;
        $n = strlen( $d );
        $k = self::hash( $v . $k );
        $o = $d;

        for( $i = 0, $j = 0; $i < $n; $i++, $j++ )
        {
            if( $j == $s )
            {
                $k = self::hash( substr( $e ? $o : $d, $i - $j, $j ) . $k );
                $j = 0;
            }

            $o[$i] = $d[$i] ^ $k[$j];
        }

        return $o;
    }
}
