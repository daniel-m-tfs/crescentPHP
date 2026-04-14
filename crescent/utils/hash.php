<?php

namespace Crescent\Utils;

/**
 * Hashing seguro de senhas usando PBKDF2 (SHA-256).
 *
 * Uso:
 *   $hash = Hash::make('senha123');
 *   Hash::verify('senha123', $hash);  // true
 *   Hash::needsRehash($hash);          // false (mesmo custo)
 */
class Hash
{
    private const ALGO       = 'sha256';
    private const ITERATIONS = 100_000;
    private const KEY_LEN    = 32;
    private const SALT_LEN   = 16;
    private const VERSION    = 1;

    /**
     * Gera o hash de uma senha.
     *
     * Formato armazenado:
     *   $pbkdf2$v=1$algo=sha256$iter=100000$<salt_hex>$<hash_hex>
     */
    public static function make(string $password): string
    {
        $salt = random_bytes(self::SALT_LEN);
        $raw  = hash_pbkdf2(self::ALGO, $password, $salt, self::ITERATIONS, self::KEY_LEN, true);

        return implode('$', [
            '',
            'pbkdf2',
            'v=' . self::VERSION,
            'algo=' . self::ALGO,
            'iter=' . self::ITERATIONS,
            bin2hex($salt),
            bin2hex($raw),
        ]);
    }

    /**
     * Verifica se a senha corresponde ao hash armazenado.
     * Usa comparação em tempo constante para evitar timing attacks.
     */
    public static function verify(string $password, string $hash): bool
    {
        $parts = explode('$', $hash);

        // Formato: ['', 'pbkdf2', 'v=1', 'algo=sha256', 'iter=100000', salt, hash]
        if (count($parts) !== 7 || $parts[1] !== 'pbkdf2') {
            // Fallback: tenta password_verify para hashes bcrypt legados
            return password_verify($password, $hash);
        }

        $algo       = explode('=', $parts[3])[1];
        $iterations = (int) explode('=', $parts[4])[1];
        $salt       = hex2bin($parts[5]);
        $storedHash = $parts[6];

        $computed = bin2hex(hash_pbkdf2($algo, $password, $salt, $iterations, self::KEY_LEN, true));

        return hash_equals($storedHash, $computed);
    }

    /**
     * Indica se o hash foi gerado com parâmetros desatualizados
     * e precisa ser regenerado.
     */
    public static function needsRehash(string $hash): bool
    {
        $parts = explode('$', $hash);

        if (count($parts) !== 7 || $parts[1] !== 'pbkdf2') {
            return true;
        }

        $iterations = (int) explode('=', $parts[4])[1];
        $algo       = explode('=', $parts[3])[1];

        return $iterations < self::ITERATIONS || $algo !== self::ALGO;
    }

    /**
     * Gera um token aleatório URL-safe (hexadecimal).
     *
     * @param int $bytes Número de bytes de entropia (tamanho hex = bytes * 2).
     */
    public static function token(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * Gera um UUID v4 aleatório.
     */
    public static function uuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // versão 4
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // variante RFC 4122

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
