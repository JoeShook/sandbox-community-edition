// See https://aka.ms/new-console-template for more information
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using pki.generator;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

Console.WriteLine("Generating logicahealth PKI for local development");

MakeCa();

foreach (var sslProxyCert in SSLProxyCerts())
{
    MakeEndCert(sslProxyCert[0], sslProxyCert[1]);
}


void MakeCa()
{
    using (RSA parentRSAKey = RSA.Create(4096))
    {
        var parentReq = new CertificateRequest(
            "CN=logica-community-sandbox-TestCA, OU=Root, O=FhirLabs, L=Portland, S=Oregon, C=US",
            parentRSAKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        parentReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        parentReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign,
                true));

        parentReq.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                    new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
                    new Oid("1.3.6.1.5.5.7.3.8") // Time Stamping
                },
                true));

        parentReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

        using (var caCert = parentReq.CreateSelfSigned(
                   DateTimeOffset.UtcNow.AddDays(-1),
                   DateTimeOffset.UtcNow.AddYears(11)))
        {
            var parentBytes = caCert.Export(X509ContentType.Pkcs12, "udap-test");
            SureFhirLabsCertStore().EnsureDirectoryExists();
            File.WriteAllBytes($"{SureFhirLabsCertStore()}/logica-community-sandbox-TestCA.pfx", parentBytes);
            char[] caPem = PemEncoding.Write("CERTIFICATE", caCert.RawData);
            File.WriteAllBytes($"{SureFhirLabsCertStore()}/logica-community-sandbox-TestCA.cer",
                caPem.Select(c => (byte)c).ToArray());
            // UpdateWindowsMachineStore(caCert);

        }
    }
}


void MakeEndCert(string dn, string san)
{
    using var rootCA = new X509Certificate2($"{SureFhirLabsCertStore()}/logica-community-sandbox-TestCA.pfx", "udap-test");

    $"{SureFhirLabsCertStore()}/ssl".EnsureDirectoryExists();

    BuildSslCertificate(
        rootCA,
        dn,
        san,
        $"{SureFhirLabsCertStore()}/ssl/{san}"
    );
}

X509Certificate2 BuildSslCertificate(
        X509Certificate2? caCert,
        string distinguishedName,
        string subjectAltNames,
        string sslCertFilePath,
        string? crl = default,
        // string? buildAIAExtensionsPath = null,
        DateTimeOffset notBefore = default,
        DateTimeOffset notAfter = default)
{

    if (notBefore == default)
    {
        notBefore = DateTimeOffset.UtcNow;
    }

    if (notAfter == default)
    {
        notAfter = DateTimeOffset.UtcNow.AddYears(10);
    }


    using RSA rsaKey = RSA.Create(2048);

    var sslRequest = new CertificateRequest(
        distinguishedName,
        rsaKey,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    sslRequest.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));

    sslRequest.CertificateExtensions.Add(
        new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature,
            true));

    sslRequest.CertificateExtensions.Add(
        new X509SubjectKeyIdentifierExtension(sslRequest.PublicKey, false));

    GeneralExtensions.AddAuthorityKeyIdentifier(caCert, sslRequest);

    if (crl != null)
    {
        sslRequest.CertificateExtensions.Add(GeneralExtensions.MakeCdp(crl));
    }

    var subAltNameBuilder = new SubjectAlternativeNameBuilder();
    subAltNameBuilder.AddDnsName(subjectAltNames);
    var x509Extension = subAltNameBuilder.Build();
    sslRequest.CertificateExtensions.Add(x509Extension);

    sslRequest.CertificateExtensions.Add(
        new X509EnhancedKeyUsageExtension(
            new OidCollection {
                    new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                    new Oid("1.3.6.1.5.5.7.3.1"), // TLS Server auth
            },
            true));

    var clientCert = sslRequest.Create(
        caCert,
        notBefore,
        notAfter,
        new ReadOnlySpan<byte>(RandomNumberGenerator.GetBytes(16)));
    // Do something with these certs, like export them to PFX,
    // or add them to an X509Store, or whatever.
    var clientCertWithKey = clientCert.CopyWithPrivateKey(rsaKey);


    var certPackage = new X509Certificate2Collection();
    certPackage.Add(clientCertWithKey);
    certPackage.Add(new X509Certificate2(caCert.Export(X509ContentType.Cert)));

    var clientBytes = certPackage.Export(X509ContentType.Pkcs12, "udap-test");
    File.WriteAllBytes($"{sslCertFilePath}.pfx", clientBytes);
    var clientPem = PemEncoding.Write("CERTIFICATE", clientCert.RawData);
    File.WriteAllBytes($"{sslCertFilePath}.cer", clientPem.Select(c => (byte)c).ToArray());
    File.WriteAllBytes($"{sslCertFilePath}.pem", clientPem.Select(c => (byte)c).ToArray());

    var key = PemEncoding.Write("RSA PRIVATE KEY", rsaKey.ExportRSAPrivateKey());
    File.WriteAllBytes($"{sslCertFilePath}.key", key.Select(c => (byte)c).ToArray());

    return clientCert;
}


static string BaseDir()
{
    var assembly = Assembly.GetExecutingAssembly();
    var resourcePath = String.Format(
        $"{Regex.Replace(assembly.ManifestModule.Name, @"\.(exe|dll)$", string.Empty, RegexOptions.IgnoreCase)}" +
        $".Resources.ProjectDirectory.txt");

    var rm = new ResourceManager("Resources", assembly);
    using var stream = assembly.GetManifestResourceStream(resourcePath);
    using var streamReader = new StreamReader(stream!);

    return streamReader.ReadToEnd().Trim();
}


static string SureFhirLabsCertStore()
{
    return $"{BaseDir()}/certstores/nginx_proxy_ssl";
}


static IEnumerable<List<string>> SSLProxyCerts()
{
    yield return new List<string>
    {
            "CN=keycloak",                  //DistinguishedName
            "keycloak"                      //SubjAltName
    };

    yield return new List<string>
    {
        "CN=sandbox",                       //DistinguishedName
        "sandbox"                      //SubjAltName
    };
    yield return new List<string>
    {
            "CN=sandbox-manager-api",       //DistinguishedName
            "sandbox-manager-api"           //SubjAltName
    };

    yield return new List<string>
    {
        "CN=stu3",                        //DistinguishedName
        "stu3"                            //SubjAltName
    };

    yield return new List<string>
    {
        "CN=stu4",                        //DistinguishedName
        "stu4"                            //SubjAltName
    };

    yield return new List<string>
    {
        "CN=stu5",                        //DistinguishedName
        "stu5"                            //SubjAltName
    };
}

