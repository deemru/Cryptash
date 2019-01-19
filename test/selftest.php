<?php

require __DIR__ . '/../vendor/autoload.php';
use deemru\Cryptash;

$cryptash = new Cryptash( 'Password' );
$msg = 'Hello, world!';

$encrypted = $cryptash->encryptash( $msg );
$decrypted = $cryptash->decryptash( $encrypted );

if( $decrypted !== $msg )
    exit( 1 );

function test_secqru_cryptash()
{
    $hashes = array( 'md5', 'sha1', 'sha256', 'gost' );
    $pass_sizes = array( 32 );
    $sizes = array( 1337 );
    $ivszs = array( 4 );
    $macszs = array( 4 );

    if( version_compare( PHP_VERSION, '5.6.0' ) >= 0 )
    {
        $pass_sizes = array_merge( $pass_sizes, array( 0, 1, 16, 128 ) );
        $sizes = array_merge( $sizes, array( 0, 1, 3, 7, 31, 32, 33, 337 ) );
        $ivszs = array_merge( $ivszs, array( 0, 1, 2, 3, 8, 16, 32 ) );
        $macszs = array_merge( $macszs, array( 0, 1, 2, 3, 8, 16, 32 ) );
    }

    foreach( $hashes as $hash )
    {
        $t = microtime( true );
        foreach( $pass_sizes as $pass_size )
        foreach( $ivszs as $ivsz )
        foreach( $macszs as $macsz )
        {
            $pass = Cryptash::rnd( $pass_size );

            $encryptash = new Cryptash( $pass, $ivsz, $macsz, $hash );
            $decryptash = new Cryptash( $pass, $ivsz, $macsz, $hash );

            foreach( $sizes as $size )
            {
                $rnd = Cryptash::rnd( $size );

                $encoded = $encryptash->encryptash( $rnd );
                $decoded = $decryptash->decryptash( $encoded );

                if( $decoded !== $rnd )
                {
                    echo 'ERROR: ';
                    var_dump( $pass );
                    var_dump( $ivsz );
                    var_dump( $macsz );
                    var_dump( $hash );
                    var_dump( bin2hex( $rnd ) );
                    var_dump( bin2hex( $encoded ) );
                    var_dump( bin2hex( $decoded ) );
                    var_dump( $encryptash );
                    exit( 1 );
                }
            }
        }

        echo sprintf( "$hash: %d ms\r\n", round( 1000 * ( microtime( true ) - $t ) ) );
    }
}

$t_start = microtime( true );
test_secqru_cryptash();
echo sprintf( "--\r\nSUCCESS: %d ms\r\n", round( 1000 * ( microtime( true ) - $t_start ) ) );
