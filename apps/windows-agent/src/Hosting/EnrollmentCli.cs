using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Crypto;
using Vajra.WindowsAgent.Identity;
using Vajra.WindowsAgent.Networking;

namespace Vajra.WindowsAgent.Hosting;

/// <summary>
/// Interactive enrollment: requires a one-time token + challenge from the web console (Plane 1 initiate).
/// Owner must confirm enrollment in the console after submit (Plane 1 confirm → TRUSTED).
/// </summary>
public static class EnrollmentCli
{
    public static async Task<int> RunAsync(
        AgentOptions options,
        DeviceIdentityStore store,
        VajraApiClient api,
        ILogger logger,
        string[] args,
        CancellationToken ct)
    {
        // Args: enroll --token <token> --device-id <uuid> --challenge-nonce <hex>
        string? token = null;
        string? deviceId = null;
        string? challengeNonce = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--token" && i + 1 < args.Length) token = args[++i];
            else if (args[i] == "--device-id" && i + 1 < args.Length) deviceId = args[++i];
            else if (args[i] == "--challenge-nonce" && i + 1 < args.Length) challengeNonce = args[++i];
        }

        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(deviceId) ||
            string.IsNullOrWhiteSpace(challengeNonce))
        {
            Console.Error.WriteLine(
                "Usage: Vajra.WindowsAgent enroll --token <TOKEN> --device-id <UUID> --challenge-nonce <HEX>");
            Console.Error.WriteLine(
                "Obtain TOKEN, device id, and challenge nonce from the VAJRA web console enrollment flow.");
            return 2;
        }

        var (identity, key) = store.CreateNewEcdsaIdentity(options.ServerBaseUrl);
        identity.DeviceId = deviceId.Trim();
        store.SaveIdentity(identity);

        var timestamp = DeviceRequestSigner.UtcTimestampIso();
        var clientNonce = DeviceRequestSigner.NewNonce();
        var transcript = DeviceRequestSigner.BuildEnrollmentTranscript(
            deviceId, token, challengeNonce, identity.PublicKeyFingerprint, timestamp, clientNonce);
        var signature = DeviceRequestSigner.SignTranscript(transcript, key);
        key.Dispose();

        var body = new
        {
            enrollmentToken = token.Trim(),
            publicKeyPem = identity.PublicKeyPem,
            keyAlgorithm = "ECDSA_P256",
            signatureBase64 = signature,
            timestampIso = timestamp,
            clientNonce,
        };

        logger.LogInformation("Submitting enrollment PoP for device {DeviceId} (token redacted).", deviceId);
        using var response = await api.EnrollmentSubmitAsync(body, ct).ConfigureAwait(false);
        var responseText = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            logger.LogError("Enrollment submit failed: HTTP {Status}. Body length={Len}",
                (int)response.StatusCode, responseText.Length);
            Console.Error.WriteLine($"Enrollment failed: HTTP {(int)response.StatusCode}");
            return 1;
        }

        identity.LifecycleState = "ENROLLMENT_PENDING";
        identity.EnrolledAt = DateTimeOffset.UtcNow;
        store.SaveIdentity(identity);

        Console.WriteLine("Enrollment public key submitted successfully.");
        Console.WriteLine($"Device ID: {deviceId}");
        Console.WriteLine($"Fingerprint: {identity.PublicKeyFingerprint}");
        Console.WriteLine("Next step: confirm the device in the VAJRA web console (owner session).");
        Console.WriteLine("The agent will only fully operate after lifecycle reaches TRUSTED/ACTIVE.");
        return 0;
    }
}
