using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Options;

// Provisions an IoT device with an mTLS identity, then lets the device authenticate
// with it.
//
// Two halves, and the split between them is the point.
//
// The OPERATOR half (`provision`) runs once, on a machine an administrator controls,
// against an authenticated CONTRACT.md §27 management client. It creates the device's
// service account, mints a Device certificate from the tenant's signing CA, binds the
// two, and writes the private key to disk. That key is returned by exactly one call and
// never again (§27.5) — no later `get` has a field where it was — so losing the response
// means revoking the certificate and minting another.
//
// The DEVICE half (`run`) runs on the device, forever after, with no password and no
// management access at all. It presents the certificate and key as a §6.1 mutual-TLS
// identity and does nothing else privileged.
//
// Run: dotnet run --project examples/DeviceMtlsProvisioning -- provision sensor-42
//      dotnet run --project examples/DeviceMtlsProvisioning -- run     sensor-42
//      dotnet run --project examples/DeviceMtlsProvisioning -- revoke  sensor-42

string baseUrl = Env("AXIAM_BASE_URL", "https://localhost:8443");
string tenant = Env("AXIAM_TENANT", "acme");
string admin = Env("AXIAM_ADMIN", "admin@example.com");
string adminPassword = Env("AXIAM_ADMIN_PASSWORD", string.Empty);
string identityDir = Env("AXIAM_DEVICE_DIR", "./device-identity");

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: provision|run|revoke <device-name>");
    return 2;
}

string device = args[1];
try
{
    switch (args[0])
    {
        case "provision":
            await ProvisionAsync(device);
            break;
        case "run":
            await RunAsync(device);
            break;
        case "revoke":
            await RevokeAsync(device);
            break;
        default:
            Console.Error.WriteLine("usage: provision|run|revoke <device-name>");
            return 2;
    }
}
catch (ValidationError e)
{
    // §27.4 rule 7: the server rejected the input, and said which parts.
    Console.Error.WriteLine($"rejected: {e.Message} [{string.Join(", ", e.Fields.Select(f => f.Field))}]");
    return 1;
}

return 0;

// Creates the device's identity and writes it to disk, once. Every step is a §27
// management write, and §27.4 rule 8 does not retry writes — generating a certificate
// twice mints two, and only one of them ends up on the device.
async Task ProvisionAsync(string name)
{
    using AxiamClient client = OperatorClient();
    await client.LoginAsync(admin, adminPassword);

    // 1. The signing CA this tenant's device certificates chain to. {org_id} defaults
    //    from the client (§27.4 rule 3). {tenant_id} does NOT on this route: under
    //    CaCertificates it names the tenant being administered rather than the calling
    //    context, so it is an ordinary argument — which is what ResolvedTenantId is
    //    public for.
    Guid tenantId = client.ResolvedTenantId
        ?? throw new InvalidOperationException(
            "login did not resolve a tenant UUID; cannot address signing CAs");

    CaCertificate issuer =
        (await client.Management.CaCertificates.ListSigningCasAllAsync(
            tenantId, start: PageRequest.Of(100)))
        .FirstOrDefault(ca => ca.Status == CertificateStatus.Active)
        ?? throw new InvalidOperationException(
            $"tenant '{tenant}' has no active signing CA; generate one with " +
            "CaCertificates.GenerateSigningCaAsync(...) before provisioning devices");

    // 2. The service account the device authenticates as.
    ServiceAccountCreatedResponse account;
    try
    {
        account = await client.Management.ServiceAccounts.CreateAsync(
            new CreateServiceAccountRequest
            {
                Description = $"IoT device {name}, mTLS identity",
                Name = name,
            });
    }
    catch (ConflictError e)
    {
        // Already provisioned. Re-minting a certificate for an existing account is a
        // decision an operator should make deliberately, so this stops rather than
        // quietly issuing a second identity.
        throw new InvalidOperationException(
            $"a service account named '{name}' already exists; revoke its certificate and " +
            $"delete it first, or pick another name ({e.Message})", e);
    }

    // 3. The certificate. PrivateKeyPem comes back from THIS call and no other —
    //    Certificates.GetAsync has no field where it was.
    GeneratedCertificate certificate = await client.Management.Certificates.GenerateAsync(
        new CreateCertificateRequest
        {
            CertType = CertificateType.Device,
            IssuerCaId = issuer.Id,
            KeyAlgorithm = KeyAlgorithm.Ed25519,
            Subject = $"CN={name},OU=devices,O={tenant}",
            ValidityDays = 825,
        });

    // 4. Write it down before doing anything else that could fail. The key is a
    //    Sensitive, so Expose() is the one explicit unwrap (§27.5) — printing
    //    `certificate` anywhere shows [SENSITIVE].
    Directory.CreateDirectory(identityDir);
    WriteSecret(Path.Combine(identityDir, $"{name}-key.pem"), certificate.PrivateKeyPem.Expose());
    await File.WriteAllTextAsync(
        Path.Combine(identityDir, $"{name}-cert.pem"),
        certificate.PublicCertPem + (certificate.ChainPem ?? string.Empty));

    // 5. Bind the certificate to the account, so presenting it authenticates as that
    //    principal.
    await client.Management.ServiceAccounts.BindCertificateAsync(
        account.Id, new BindCertificate { CertificateId = certificate.Id });

    Console.WriteLine($"provisioned {name}");
    Console.WriteLine($"  service account : {account.Id}");
    Console.WriteLine($"  certificate     : {certificate.Id} ({certificate.Fingerprint})");
    Console.WriteLine($"  valid until     : {certificate.NotAfter:O}");
    Console.WriteLine($"  identity written: {identityDir}/");
}

// Authenticates as the device, with the identity provisioning wrote. No password, no
// management surface, no secret in the environment — the private key on disk IS the
// credential. Presenting it never relaxes server verification (§6.1 rule 2): strict TLS
// stays fully on.
async Task RunAsync(string name)
{
    string certPath = Path.Combine(identityDir, $"{name}-cert.pem");
    string keyPath = Path.Combine(identityDir, $"{name}-key.pem");
    if (!File.Exists(certPath) || !File.Exists(keyPath))
    {
        throw new InvalidOperationException(
            $"no identity for '{name}' in {identityDir}/; provision it first");
    }

    using var deviceClient = new AxiamClient(
        new Uri(baseUrl),
        tenant,
        new AxiamClientOptions
        {
            BaseUrl = new Uri(baseUrl),
            TenantId = tenant,
            ClientCertificatePem = await File.ReadAllBytesAsync(certPath),
            ClientKeyPem = await File.ReadAllBytesAsync(keyPath),
        });

    bool allowed = await deviceClient.Authz.CanAsync("telemetry:publish", Guid.Empty);
    Console.WriteLine($"{name} may publish telemetry: {allowed}");
}

// Revokes the device's certificate — the decommissioning path. Deleting the service
// account alone leaves a valid certificate in the field; revoking the certificate is
// what actually stops the device authenticating.
async Task RevokeAsync(string name)
{
    using AxiamClient client = OperatorClient();
    await client.LoginAsync(admin, adminPassword);

    ServiceAccountResponse account =
        (await client.Management.ServiceAccounts.ListAllAsync(start: PageRequest.Of(200)))
        .FirstOrDefault(a => a.Name == name)
        ?? throw new InvalidOperationException($"no service account named '{name}'");

    foreach (Certificate certificate in
             await client.Management.Certificates.ListAllAsync(start: PageRequest.Of(200)))
    {
        if (!certificate.Subject.StartsWith($"CN={name},", StringComparison.Ordinal))
        {
            continue;
        }

        try
        {
            await client.Management.Certificates.RevokeAsync(certificate.Id);
        }
        catch (NotFoundError)
        {
            continue;
        }

        Console.WriteLine($"revoked {certificate.Id}");
    }

    await client.Management.ServiceAccounts.DeleteAsync(account.Id);
    Console.WriteLine($"deleted service account {account.Id}");
}

AxiamClient OperatorClient() => new(
    new Uri(baseUrl),
    tenant,
    new AxiamClientOptions { BaseUrl = new Uri(baseUrl), TenantId = tenant, OrgSlug = tenant });

// Writes `content` readable only by this user. The mode is set at creation rather than
// afterwards: a chmod after the fact leaves a window in which the key is world-readable,
// which on a shared provisioning host is the whole exposure.
static void WriteSecret(string path, string content)
{
    if (File.Exists(path))
    {
        File.Delete(path);
    }

    using (FileStream stream = File.Create(path))
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        using var writer = new StreamWriter(stream);
        writer.Write(content);
    }
}

static string Env(string name, string fallback) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;
