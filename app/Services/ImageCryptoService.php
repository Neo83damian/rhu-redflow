<?php

namespace App\Services;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

/**
 * Encrypts uploaded ID front/back photos and selfies before saving them
 * (in the database, so they survive Railway redeploys), and decrypts them on the fly for viewing. Uses Laravel's built-in
 * Crypt facade (AES-256-CBC, keyed off APP_KEY in .env) so no extra crypto
 * setup is needed — this is the Laravel equivalent of the crypto.php
 * AES-256 helper used in the XAMPP/PHP version of REDFLOW.
 */
class ImageCryptoService
{
    /**
     * Accepts a base64 data URL (e.g. "data:image/png;base64,....") as sent
     * by the signup wizard / camera capture / file upload inputs, encrypts
     * the raw bytes, and stores them on the private "secure" disk.
     *
     * @return string|null The stored (encrypted) file path, or null if no image was provided.
     */
    public function storeEncrypted(?string $base64DataUrl, string $folder): ?string
    {
        if (empty($base64DataUrl)) {
            return null;
        }

        if (str_contains($base64DataUrl, ',')) {
            [, $base64DataUrl] = explode(',', $base64DataUrl, 2);
        }

        $rawBytes = base64_decode($base64DataUrl, true);
        if ($rawBytes === false) {
            return null;
        }

        $encrypted = Crypt::encrypt($rawBytes);
        $path = trim($folder, '/') . '/' . Str::uuid() . '.enc';

        // Preferred: keep the encrypted photo in the database. Hosts like
        // Railway wipe the server's disk on every redeploy/restart, which
        // used to make ID/selfie photos "expire"; the database is persistent.
        if (Schema::hasTable('secure_files')) {
            DB::table('secure_files')->insert([
                'path' => $path,
                'content' => $encrypted,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            return $path;
        }

        // Fallback (migration not run yet): old disk storage.
        Storage::disk('secure')->put($path, $encrypted);

        return $path;
    }

    /**
     * Decrypts a stored image back to raw bytes for display (used by the
     * admin Approval & Verification photo zoom modal, and profile avatars).
     */
    public function decrypt(string $storedPath): ?string
    {
        try {
            if (Schema::hasTable('secure_files')) {
                $row = DB::table('secure_files')->where('path', $storedPath)->first();
                if ($row) {
                    return Crypt::decrypt($row->content);
                }
            }

            // Older photos saved to disk before the database storage existed.
            if (Storage::disk('secure')->exists($storedPath)) {
                return Crypt::decrypt(Storage::disk('secure')->get($storedPath));
            }
        } catch (\Exception $e) {
            return null;
        }

        return null;
    }

    /**
     * Removes a stored photo (database copy and/or old disk copy).
     */
    public function delete(?string $storedPath): void
    {
        if (empty($storedPath)) {
            return;
        }

        try {
            if (Schema::hasTable('secure_files')) {
                DB::table('secure_files')->where('path', $storedPath)->delete();
            }
            if (Storage::disk('secure')->exists($storedPath)) {
                Storage::disk('secure')->delete($storedPath);
            }
        } catch (\Exception $e) {
            // Best-effort cleanup only.
        }
    }
}
