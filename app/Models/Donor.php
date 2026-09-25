<?php

namespace App\Models;

use App\Casts\SafeEncrypted;
use App\Casts\SafeEncryptedArray;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Donor extends Model
{
    use HasFactory;

    protected $fillable = [
        'donor_uid', 'name', 'ext_name', 'blood_type', 'contact', 'brgy', 'gender', 'dob', 'avatar_path', 'extra',
    ];

    // Personal details are stored ENCRYPTED in the database (name, extended
    // name, blood type, contact number, and the whole `extra` block that
    // repeats them plus emergency contact, allergies, etc.). They are
    // decrypted automatically whenever a Donor is read, so the rest of the
    // app (and the frontend) sees normal text.
    protected $casts = [
        'name' => SafeEncrypted::class,
        'ext_name' => SafeEncrypted::class,
        'blood_type' => SafeEncrypted::class,
        'contact' => SafeEncrypted::class,
        'dob' => 'date',
        'extra' => SafeEncryptedArray::class,
    ];

    public function monitoringRecords()
    {
        return $this->hasMany(MonitoringRecord::class);
    }

    public function monitoringTransactions()
    {
        return $this->hasMany(MonitoringTransaction::class);
    }

    /**
     * The frontend (script-legacy.js) works with one flat donor object that
     * has many fields (weight, allergies, emergencyContactName, etc.) beyond
     * what's indexed in dedicated columns. Rather than re-modeling every one
     * of those fields relationally (risking a mismatch with the existing,
     * working frontend logic), the full object is stored verbatim in
     * `extra` and returned as-is, with `id` always set to the real DB id.
     */
    public function toFrontendArray(): array
    {
        return array_merge($this->extra ?? [], [
            'id' => $this->id,
            'name' => $this->name,
            'bloodType' => $this->blood_type,
            'brgy' => $this->brgy,
            'contact' => $this->contact,
            'avatar' => $this->avatar_path ?: 'picture.jpg',
        ]);
    }
}
