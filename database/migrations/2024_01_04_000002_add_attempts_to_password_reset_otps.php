<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Counts wrong guesses against each emailed code. After 5 wrong guesses the
 * code is burned, so the 6-digit code can't be brute-forced (there are only
 * one million possible codes; without this an automated script could try
 * them all inside the 10 minutes a code is valid).
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('password_reset_otps') && !Schema::hasColumn('password_reset_otps', 'attempts')) {
            Schema::table('password_reset_otps', function (Blueprint $table) {
                $table->unsignedTinyInteger('attempts')->default(0)->after('consumed');
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasColumn('password_reset_otps', 'attempts')) {
            Schema::table('password_reset_otps', function (Blueprint $table) {
                $table->dropColumn('attempts');
            });
        }
    }
};
