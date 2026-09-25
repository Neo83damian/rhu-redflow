<?php

namespace App\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Contracts\Database\Eloquent\ComparesCastableAttributes;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;

/**
 * Stores a text value ENCRYPTED (AES-256, using the app's APP_KEY) in the
 * database and gives the decrypted text back when the model is read.
 *
 * "Safe" = if a row still holds an old, not-yet-encrypted (plain) value —
 * for example right before the encrypt-existing-data migration has run —
 * it is returned as-is instead of crashing, so the site never breaks while
 * data is being converted. Every new save is always encrypted.
 */
class SafeEncrypted implements CastsAttributes, ComparesCastableAttributes
{
    public function get($model, string $key, $value, array $attributes)
    {
        if ($value === null || $value === '') {
            return $value;
        }

        try {
            return Crypt::decryptString($value);
        } catch (DecryptException $e) {
            return $value; // legacy plain-text row
        }
    }

    public function set($model, string $key, $value, array $attributes)
    {
        if ($value === null) {
            return null;
        }

        return Crypt::encryptString((string) $value);
    }

    /**
     * Encryption uses a random IV, so the same text never encrypts to the
     * same string twice. Compare the DECRYPTED values instead, so saving a
     * donor without changing anything is still correctly seen as "no change"
     * (the Audit Log only records real changes).
     */
    public function compare($model, string $key, $firstValue, $secondValue): bool
    {
        return $this->get($model, $key, $firstValue, []) === $this->get($model, $key, $secondValue, []);
    }
}
