<?php

namespace App\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Contracts\Database\Eloquent\ComparesCastableAttributes;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;

/**
 * Same idea as SafeEncrypted, for the JSON "extra" columns (the full donor /
 * record object the frontend keeps: name, blood type, contact, emergency
 * contact, allergies, ...). The whole array is encrypted as one block, so no
 * personal detail sits readable inside the database.
 *
 * Old rows that still contain plain JSON are read normally (see SafeEncrypted).
 */
class SafeEncryptedArray implements CastsAttributes, ComparesCastableAttributes
{
    public function get($model, string $key, $value, array $attributes)
    {
        if ($value === null || $value === '') {
            return null;
        }

        try {
            $json = Crypt::decryptString($value);
        } catch (DecryptException $e) {
            $json = $value; // legacy plain JSON row
        }

        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : null;
    }

    public function set($model, string $key, $value, array $attributes)
    {
        if ($value === null) {
            return null;
        }

        return Crypt::encryptString(json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    public function compare($model, string $key, $firstValue, $secondValue): bool
    {
        return $this->get($model, $key, $firstValue, []) == $this->get($model, $key, $secondValue, []);
    }
}
