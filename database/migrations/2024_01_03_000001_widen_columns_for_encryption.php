<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Encrypted values are much longer than the plain text they hide (a 10-letter
 * name becomes ~200 characters), so the columns that will hold encrypted data
 * must be TEXT instead of a 255-character string, and JSON "extra" columns
 * must become plain text (an encrypted block is not valid JSON).
 *
 * Raw SQL per database type is used on purpose so this works no matter which
 * Laravel version / packages are installed.
 */
return new class extends Migration
{
    public function up(): void
    {
        // The search indexes on the (now encrypted) name / blood type columns
        // are useless — encrypted text can't be searched by the database (the
        // app filters in the browser) — and MySQL refuses to keep a full index
        // on a TEXT column, so drop them first.
        $driver = DB::getDriverName();

        if (in_array($driver, ['mysql', 'mariadb'])) {
            foreach (['donors_name_index', 'donors_blood_type_index'] as $index) {
                try {
                    DB::statement('ALTER TABLE donors DROP INDEX ' . $index);
                } catch (\Throwable $e) {
                    // not there (already dropped) — fine
                }
            }
        } else {
            DB::statement('DROP INDEX IF EXISTS donors_name_index');
            DB::statement('DROP INDEX IF EXISTS donors_blood_type_index');
        }

        $text = [
            'donors' => ['name' => false, 'ext_name' => true, 'blood_type' => true, 'contact' => true],
            'monitoring_records' => ['blood_type' => true],
            'monitoring_transactions' => ['blood_type' => true],
            'audit_log' => ['donor_name' => true],
        ];
        $json = [
            'donors' => 'extra',
            'monitoring_records' => 'extra',
            'monitoring_transactions' => 'extra',
            'staff_profiles' => 'extra',
        ];

        foreach ($text as $table => $columns) {
            if (!Schema::hasTable($table)) {
                continue;
            }
            foreach ($columns as $column => $nullable) {
                if (!Schema::hasColumn($table, $column)) {
                    continue;
                }
                $null = $nullable ? 'NULL' : 'NOT NULL';
                if (in_array($driver, ['mysql', 'mariadb'])) {
                    DB::statement("ALTER TABLE `{$table}` MODIFY `{$column}` TEXT {$null}");
                } elseif ($driver === 'pgsql') {
                    DB::statement("ALTER TABLE \"{$table}\" ALTER COLUMN \"{$column}\" TYPE TEXT");
                }
                // sqlite: string columns already accept any length — nothing to do
            }
        }

        foreach ($json as $table => $column) {
            if (!Schema::hasTable($table) || !Schema::hasColumn($table, $column)) {
                continue;
            }
            if (in_array($driver, ['mysql', 'mariadb'])) {
                DB::statement("ALTER TABLE `{$table}` MODIFY `{$column}` LONGTEXT NULL");
            } elseif ($driver === 'pgsql') {
                DB::statement("ALTER TABLE \"{$table}\" ALTER COLUMN \"{$column}\" TYPE TEXT USING \"{$column}\"::text");
            }
        }
    }

    public function down(): void
    {
        // Not reversed: shrinking the columns back would cut off encrypted data.
    }
};
