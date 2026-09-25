<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Stores the AES-256-encrypted ID / selfie photos INSIDE the database
 * instead of on the server's disk.
 *
 * Why: Railway's container filesystem is temporary — every redeploy or
 * restart wipes storage/app/secure, so uploaded ID/selfie photos "expired"
 * (the Approval Verification thumbnails fell back to the placeholder). The
 * MySQL database on Railway is persistent, so photos kept here stay forever
 * (until the staff account itself is deleted/rejected).
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('secure_files')) {
            return;
        }

        Schema::create('secure_files', function (Blueprint $table) {
            $table->id();
            $table->string('path')->unique();   // e.g. "ids/<uuid>.enc" — same value stored in users.*_path
            $table->longText('content');        // Laravel Crypt (AES-256) payload of the image bytes
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('secure_files');
    }
};
