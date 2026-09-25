<?php

namespace App\Http\Controllers;

use App\Models\AppNotification;
use App\Models\AuditLog;
use App\Models\PasswordResetOtp;
use App\Models\User;
use App\Support\ActivityLog;
use App\Support\LoginAlert;
use App\Services\ImageCryptoService;
use App\Services\OtpEmailSender;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    protected const MAX_ATTEMPTS = 5;
    protected const LOCKOUT_SECONDS = 60;

    public function showEntry()
    {
        // Serves the single-shell page (login view + all modals + the shared
        // staff/admin app container) — the frontend JS handles which parts
        // are visible, exactly as in the original DOME-4-1-2.html prototype.
        return view('entry');
    }

    public function login(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $email = strtolower($data['email']);
        $user = User::where('email', $email)->first();

        if ($user && $user->isLocked()) {
            // Whole seconds only (e.g. "60", never "46.513017"). Carbon 3's
            // diffInSeconds() returns a float with decimals, so round UP.
            $seconds = max(1, (int) ceil(now()->diffInSeconds($user->locked_until, false)));
            return response()->json([
                'message' => "Error: Too many failed login attempts. Please wait {$seconds} second(s) before trying again.",
            ], 423);
        }

        if (!$user || !Hash::check($data['password'], $user->password)) {
            if ($user) {
                ActivityLog::userEvent($user->id, 'failed_login', $request->ip());
                $user->failed_login_attempts++;
                if ($user->failed_login_attempts >= self::MAX_ATTEMPTS) {
                    $user->locked_until = now()->addSeconds(self::LOCKOUT_SECONDS);
                    $user->failed_login_attempts = 0;
                    // Tell the real owner that someone is guessing their password.
                    LoginAlert::queueLockout($user, $request);
                }
                $user->save();
            }
            return response()->json(['message' => 'Error: Incorrect Email or Password! Please check your credentials.'], 401);
        }

        if ($user->status === 'Pending') {
            return response()->json(['message' => 'Your Staff Account is still waiting for Admin approval.'], 403);
        }

        // Correct credentials — clear any prior failed-attempt lockout state
        $user->failed_login_attempts = 0;
        $user->locked_until = null;
        $user->last_login_at = now();
        $user->save();

        Auth::login($user);
        $request->session()->regenerate();

        ActivityLog::userEvent($user->id, 'login', $request->ip());
        ActivityLog::syncStaffProfile($user);

        // Defense-in-depth against duplicate login notifications: if a
        // double-click/double-submit still slips a second /login request
        // through within a few seconds, don't create a second identical
        // notification for the same account.
        $recentDuplicate = AppNotification::where('user_id', $user->id)
            ->where('message', 'like', 'Your account (%) was logged in and used.')
            ->where('created_at', '>=', now()->subSeconds(10))
            ->exists();

        if (!$recentDuplicate) {
            // No date/time is baked into the message text itself — the
            // notification's stored created_at timestamp is the single
            // source of truth, and the frontend renders it consistently
            // (formatLoginTimestamp) everywhere a timestamp is shown. An
            // embedded date here (server timezone, plain text) used to be
            // able to show a different date/time than the footer below it
            // (client-rendered from the same event's real timestamp).
            AppNotification::create([
                'user_id' => $user->id,
                'message' => "Your account ({$user->role}) was logged in and used.",
            ]);

            // Email alert to the account owner (sent after the response, so
            // login stays fast and never fails because of the mail service).
            LoginAlert::queue($user, $request);
        }

        AuditLog::record($user->id, 'login', "{$user->name} ({$user->role}) logged in.");

        // Like logout(), session()->regenerate() above also rotates the CSRF
        // token for security. Since this is a single-page app (no full page
        // reload happens after a successful login), the frontend needs the
        // new token sent back so it can refresh its <meta name="csrf-token">
        // tag — otherwise the very next POST/PUT/DELETE after logging in
        // (change password, create a donor, etc.) would fail with a 419
        // "CSRF token mismatch".
        return response()->json([
            'user' => $user->toFrontendArray(),
            'csrf_token' => csrf_token(),
        ]);
    }

    public function register(Request $request, ImageCryptoService $crypto)
    {
        $data = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => $this->passwordRules(),
            'contact' => 'required|string|max:50',
            'brgy' => 'required|string|max:255',
            'gender' => 'nullable|string|max:50',
            'dob' => 'nullable|date',
            // max ~8 MB of base64 text per photo, so nobody can flood the
            // database with giant uploads.
            'idFront' => 'nullable|string|max:8000000',
            'idBack' => 'nullable|string|max:8000000',
            'faceDoc' => 'nullable|string|max:8000000',
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => strtolower($data['email']),
            'password' => $data['password'], // hashed automatically via the 'hashed' cast on the model
            'contact' => $data['contact'],
            'brgy' => $data['brgy'],
            'gender' => $data['gender'] ?? null,
            'dob' => $data['dob'] ?? null,
            'role' => 'Staff',
            'status' => 'Pending',
            'action_taken' => 'Registered',
            'id_front_path' => $crypto->storeEncrypted($data['idFront'] ?? null, 'ids'),
            'id_back_path' => $crypto->storeEncrypted($data['idBack'] ?? null, 'ids'),
            'face_doc_path' => $crypto->storeEncrypted($data['faceDoc'] ?? null, 'selfies'),
        ]);

        AuditLog::record($user->id, 'register', "{$user->name} submitted a Staff sign-up request.");
        ActivityLog::userEvent($user->id, 'register', $request->ip());
        ActivityLog::syncStaffProfile($user);
        ActivityLog::notifyAdmins("New Staff sign-up request from {$user->name} is waiting for your approval.");

        return response()->json(['user' => $user->toFrontendArray()], 201);
    }

    public function logout(Request $request)
    {
        if ($user = Auth::user()) {
            AuditLog::record($user->id, 'logout', "{$user->name} logged out.");
            ActivityLog::userEvent($user->id, 'logout', $request->ip());
        }
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // Since the frontend does NOT reload the page after logout (it just
        // swaps the visible view back to the login screen, to stay a true
        // single-page app), the <meta name="csrf-token"> embedded at the
        // original page load is now stale — the line above just rotated it
        // for security. Sending the new token back here lets the frontend
        // update that meta tag in place, so the very next login/forgot-
        // password request isn't rejected with a 419 "CSRF token mismatch".
        return response()->json([
            'message' => 'Logged out.',
            'csrf_token' => csrf_token(),
        ]);
    }

    public function changePassword(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|email',
            'code' => 'required|string',
            'current_password' => 'required|string',
            'password' => $this->passwordRules(),
            'new_email' => 'nullable|email',
        ]);

        $user = Auth::user();
        if (!$user) {
            return response()->json(['message' => 'Error: No logged in account found.'], 401);
        }

        // The email code is checked HERE on the server too (not just in the
        // browser), so the password can't be changed without it.
        $email = strtolower($data['email']);
        $otp = $email === strtolower($user->email) ? $this->findValidOtp($email, $data['code']) : null;
        if (!$otp) {
            return response()->json(['message' => 'Error: Invalid or expired verification code. Please request a new code.'], 422);
        }

        if (!Hash::check($data['current_password'], $user->password)) {
            return response()->json(['message' => 'Error: Current Password is incorrect.'], 422);
        }

        // Optional: the person typed a NEW email address on the last step.
        // Only allowed after the code + current password above have proven it
        // is really them, and never onto an address another account uses.
        $newEmail = isset($data['new_email']) ? strtolower($data['new_email']) : null;
        $emailChanged = $newEmail !== null && $newEmail !== strtolower($user->email);
        if ($emailChanged && User::where('email', $newEmail)->where('id', '!=', $user->id)->exists()) {
            return response()->json(['message' => 'Error: That email address is already used by another account.'], 422);
        }

        $user->password = $data['password']; // re-hashed automatically via the model cast
        if ($emailChanged) {
            $user->email = $newEmail;
        }
        $user->save();

        if ($emailChanged) {
            AuditLog::record($user->id, 'change_email', "{$user->name} changed their account email address.");
            ActivityLog::userEvent($user->id, 'change_email', $request->ip());
            ActivityLog::notifyUser($user->id, 'Your account email address was changed.');
            ActivityLog::syncStaffProfile($user);
        }

        // The code is single-use: burn it (and any other still-open code for
        // this email) now that the password has been changed.
        PasswordResetOtp::where('email', $email)->where('consumed', false)->update(['consumed' => true]);

        AuditLog::record($user->id, 'change_password', "{$user->name} changed their password.");
        ActivityLog::userEvent($user->id, 'change_password', $request->ip());
        ActivityLog::notifyUser($user->id, 'Your password was changed successfully.');
        // Also visible on the app's Audit Log page (red "Change" badge).
        // Details is always the literal text "Change Password" — the
        // actual password (old or new) is never written to the log.
        AuditLog::recordDonorAction($user->id, 'Change', null, null, 'Change Password');

        return response()->json(['message' => 'Password updated successfully!']);
    }

    public function sendOtp(Request $request, OtpEmailSender $mailer)
    {
        $data = $request->validate(['email' => 'required|email']);
        $email = strtolower($data['email']);

        $user = User::where('email', $email)->first();
        if (!$user) {
            return response()->json(['message' => 'Error: No account found with that email address.'], 404);
        }

        if ($error = $this->issueOtp($email, $mailer, 'reset')) {
            return $error;
        }

        return response()->json(['message' => 'Verification code sent.']);
    }

    /**
     * Creates a 6-digit code (stored only as a hash, valid 10 minutes) and
     * emails it. Returns null on success, or a ready-made error response.
     */
    protected function issueOtp(string $email, OtpEmailSender $mailer, string $purpose)
    {
        // At most 5 codes per email every 10 minutes (stops email flooding /
        // mail-bombing someone's inbox through the "Send code" button).
        $recent = PasswordResetOtp::where('email', $email)->where('created_at', '>=', now()->subMinutes(10))->count();
        if ($recent >= 5) {
            return response()->json([
                'message' => 'Too many verification code requests. Please wait a few minutes before trying again.',
            ], 429);
        }

        $code = (string) random_int(100000, 999999);

        $otp = PasswordResetOtp::create([
            'email' => $email,
            'code_hash' => Hash::make($code),
            'expires_at' => now()->addMinutes(10),
            'consumed' => false,
        ]);

        // Sends via MAIL_MAILER: "brevo"/"resend" use an HTTPS API (works on
        // Railway, which blocks SMTP ports); anything else uses normal
        // Laravel Mail (e.g. the "log" driver writes the code to
        // storage/logs/laravel.log for local testing).
        try {
            $mailer->send($email, $code, $purpose);
        } catch (\Throwable $e) {
            Log::error('OTP email failed (' . $purpose . '): ' . $e->getMessage());
            $otp->delete();
            return response()->json([
                'message' => 'Unable to send the verification email right now. Please try again in a moment or check your internet Connection.',
            ], 500);
        }

        return null;
    }

    /**
     * Change Password step 1 (logged-in users): emails a 6-digit code to the
     * account's own email address. The address typed in must match the
     * account, so nobody can send codes to (or verify with) a different email.
     */
    public function sendChangePasswordOtp(Request $request, OtpEmailSender $mailer)
    {
        $data = $request->validate(['email' => 'required|email']);
        $user = Auth::user();
        if (!$user) {
            return response()->json(['message' => 'Error: No logged in account found.'], 401);
        }

        $email = strtolower($data['email']);
        if ($email !== strtolower($user->email)) {
            return response()->json(['message' => 'Error: That email address does not match your account.'], 422);
        }

        if ($error = $this->issueOtp($email, $mailer, 'change')) {
            return $error;
        }

        return response()->json(['message' => 'Verification code sent.']);
    }

    /** Change Password step 2: checks the code (does not use it up yet). */
    public function verifyChangePasswordOtp(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|email',
            'code' => 'required|string',
        ]);
        $user = Auth::user();
        if (!$user) {
            return response()->json(['message' => 'Error: No logged in account found.'], 401);
        }

        $email = strtolower($data['email']);
        if ($email !== strtolower($user->email) || !$this->findValidOtp($email, $data['code'])) {
            return response()->json(['message' => 'Error: Invalid verification code. Please try again.'], 422);
        }

        return response()->json(['message' => 'Code verified.']);
    }

    public function verifyOtp(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|email',
            'code' => 'required|string',
        ]);

        if (!$this->findValidOtp(strtolower($data['email']), $data['code'])) {
            return response()->json(['message' => 'Error: Invalid verification code. Please try again.'], 422);
        }

        return response()->json(['message' => 'Code verified.']);
    }

    public function resetPassword(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|email',
            'code' => 'required|string',
            'password' => $this->passwordRules(),
        ]);

        $email = strtolower($data['email']);
        $otp = $this->findValidOtp($email, $data['code']);
        if (!$otp) {
            return response()->json(['message' => 'Error: Invalid or expired verification code.'], 422);
        }

        $user = User::where('email', $email)->first();
        if (!$user) {
            return response()->json(['message' => 'Error: No account found with that email address.'], 404);
        }

        $user->password = $data['password']; // re-hashed automatically via the model cast
        $user->save();

        $otp->consumed = true;
        $otp->save();

        AuditLog::record($user->id, 'password_reset', "{$user->name} reset their password via email OTP.");
        ActivityLog::userEvent($user->id, 'password_reset', $request->ip());
        ActivityLog::notifyUser($user->id, 'Your password was reset using the email verification code.');

        return response()->json(['message' => 'Password successfully reset!']);
    }

    /** Wrong guesses allowed per emailed code before it is burned. */
    private const MAX_OTP_ATTEMPTS = 5;

    /** Server-side password strength — same rule the screens show: 8+ characters with a number and a symbol. */
    protected function passwordRules(): array
    {
        return [
            'required',
            'string',
            'min:8',
            function ($attribute, $value, $fail) {
                if (!preg_match('/[0-9]/', (string) $value) || !preg_match('/[^A-Za-z0-9]/', (string) $value)) {
                    $fail('Password must be at least 8 characters long and contain both numbers and symbols.');
                }
            },
        ];
    }

    protected function otpHasAttemptsColumn(): bool
    {
        static $has = null;
        return $has ??= \Illuminate\Support\Facades\Schema::hasColumn('password_reset_otps', 'attempts');
    }

    protected function findValidOtp(string $email, string $code): ?PasswordResetOtp
    {
        $query = PasswordResetOtp::where('email', $email)
            ->where('consumed', false)
            ->where('expires_at', '>=', now());

        if ($this->otpHasAttemptsColumn()) {
            $query->where('attempts', '<', self::MAX_OTP_ATTEMPTS);
        }

        $candidates = $query->orderByDesc('id')->get();

        foreach ($candidates as $otp) {
            if (Hash::check($code, $otp->code_hash)) {
                return $otp;
            }
        }

        // Wrong guess: count it against every still-open code for this email;
        // a code that reaches the limit is burned and a new one must be requested.
        if ($this->otpHasAttemptsColumn()) {
            foreach ($candidates as $otp) {
                $otp->attempts = (int) $otp->attempts + 1;
                if ($otp->attempts >= self::MAX_OTP_ATTEMPTS) {
                    $otp->consumed = true;
                }
                $otp->save();
            }
        }

        return null;
    }
}
