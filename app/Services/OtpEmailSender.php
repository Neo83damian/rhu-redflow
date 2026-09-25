<?php

namespace App\Services;

use App\Mail\OtpMail;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use RuntimeException;

/**
 * Sends the Forgot Password OTP email.
 *
 * WHY THIS EXISTS: Railway (Free / Trial / Hobby plans) BLOCKS outgoing SMTP
 * (ports 25 / 465 / 587), so Gmail SMTP can never work there — it works on a
 * local PC but not once deployed. Sending through an email provider's HTTPS
 * API (port 443) always works on Railway.
 *
 * Choose the provider with MAIL_MAILER in the environment variables:
 *   - brevo  → Brevo HTTPS API  (recommended: free 300 emails/day, can send to
 *              ANY recipient once your sender email is verified)
 *   - resend → Resend HTTPS API (free, but without your own verified domain it
 *              can only deliver to your own account email)
 *   - smtp / log / anything else → normal Laravel Mail (local testing / Pro plan)
 *
 * For brevo/resend, put the provider's API key in MAIL_PASSWORD and the
 * verified sender email in MAIL_FROM_ADDRESS. (MAIL_PASSWORD is reused on
 * purpose: it is already part of Laravel's mail config, so this keeps working
 * even when the config is cached on the server.)
 */
class OtpEmailSender
{
    public function send(string $to, string $code, string $purpose = 'reset'): void
    {
        $provider = strtolower((string) config('mail.default'));

        if ($provider === 'brevo') {
            $this->sendViaBrevo($to, $code, $purpose);
            return;
        }

        if ($provider === 'resend') {
            $this->sendViaResend($to, $code, $purpose);
            return;
        }

        Mail::to($to)->send(new OtpMail($code, $purpose));
    }

    /**
     * Sends any ready-made HTML email (used for the login-alert emails) through
     * the same provider as the verification codes: Brevo / Resend over HTTPS
     * (works on Railway) or normal Laravel Mail otherwise.
     */
    public function sendMessage(string $to, string $subject, string $html): void
    {
        $provider = strtolower((string) config('mail.default'));

        if ($provider === 'brevo') {
            $response = Http::timeout(15)
                ->withHeaders(['api-key' => $this->apiKey(), 'accept' => 'application/json'])
                ->post('https://api.brevo.com/v3/smtp/email', [
                    'sender' => ['name' => $this->fromName(), 'email' => $this->fromAddress()],
                    'to' => [['email' => $to]],
                    'subject' => $subject,
                    'htmlContent' => $html,
                ]);
            if (!$response->successful()) {
                throw new RuntimeException('Brevo API error ' . $response->status() . ': ' . $response->body());
            }
            return;
        }

        if ($provider === 'resend') {
            $response = Http::timeout(15)
                ->withToken($this->apiKey())
                ->post('https://api.resend.com/emails', [
                    'from' => $this->fromName() . ' <' . $this->fromAddress() . '>',
                    'to' => [$to],
                    'subject' => $subject,
                    'html' => $html,
                ]);
            if (!$response->successful()) {
                throw new RuntimeException('Resend API error ' . $response->status() . ': ' . $response->body());
            }
            return;
        }

        Mail::html($html, function ($message) use ($to, $subject) {
            $message->to($to)->subject($subject);
        });
    }

    protected function apiKey(): string
    {
        $key = (string) config('mail.mailers.smtp.password');
        if ($key === '' || $key === 'null') {
            throw new RuntimeException('MAIL_PASSWORD (the email provider API key) is not set.');
        }
        return $key;
    }

    protected function fromAddress(): string
    {
        return (string) config('mail.from.address');
    }

    protected function fromName(): string
    {
        return (string) (config('mail.from.name') ?: 'REDFLOW');
    }

    protected function html(string $code, string $purpose = 'reset'): string
    {
        return (new OtpMail($code, $purpose))->render();
    }

    protected function sendViaBrevo(string $to, string $code, string $purpose = 'reset'): void
    {
        $response = Http::timeout(20)
            ->withHeaders(['api-key' => $this->apiKey(), 'accept' => 'application/json'])
            ->post('https://api.brevo.com/v3/smtp/email', [
                'sender' => ['name' => $this->fromName(), 'email' => $this->fromAddress()],
                'to' => [['email' => $to]],
                'subject' => (new OtpMail($code, $purpose))->subjectLine(),
                'htmlContent' => $this->html($code, $purpose),
            ]);

        if (!$response->successful()) {
            throw new RuntimeException('Brevo API error ' . $response->status() . ': ' . $response->body());
        }
    }

    protected function sendViaResend(string $to, string $code, string $purpose = 'reset'): void
    {
        $response = Http::timeout(20)
            ->withToken($this->apiKey())
            ->post('https://api.resend.com/emails', [
                'from' => $this->fromName() . ' <' . $this->fromAddress() . '>',
                'to' => [$to],
                'subject' => (new OtpMail($code, $purpose))->subjectLine(),
                'html' => $this->html($code, $purpose),
            ]);

        if (!$response->successful()) {
            throw new RuntimeException('Resend API error ' . $response->status() . ': ' . $response->body());
        }
    }
}
