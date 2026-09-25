<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Keeps, per account, the safety counters for "Export Donor Masterlist":
 *   - failed_attempts / locked_until : wrong-password tries (3 wrong = 60 s lock)
 *   - exports                        : times of the last successful exports
 *                                      (max 3 within 24 hours)
 *
 * Stored in the database (not in the cache or the browser) so the limits
 * survive redeploys and can't be reset by clearing the Audit Log or by
 * refreshing the page.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('export_guards')) {
            return;
        }

        Schema::create('export_guards', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained('users')->cascadeOnDelete();
            $table->unsignedTinyInteger('failed_attempts')->default(0);
            $table->timestamp('locked_until')->nullable();
            $table->text('exports')->nullable(); // JSON list of ISO timestamps
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('export_guards');
    }
};
