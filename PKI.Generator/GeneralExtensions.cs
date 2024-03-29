#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace pki.generator;

public static class GeneralExtensions
{
    public static void EnsureDirectoryExists(this string source)
    {
        if (!Directory.Exists(source))
        {
            Directory.CreateDirectory(source);
        }
    }

    public static void EnsureDirectoryExistFromFilePath(this string source)
    {
        var directoryPath = Path.GetDirectoryName(source);
        if (directoryPath != null)
        {
            EnsureDirectoryExists(directoryPath);
        }
    }

    public static void AddAuthorityKeyIdentifier(X509Certificate2 caCert, CertificateRequest intermediateReq)
    {
        //
        // Found way to generate intermediate below
        //
        // https://github.com/rwatjen/AzureIoTDPSCertificates/blob/711429e1b6dee7857452233a73f15c22c2519a12/src/DPSCertificateTool/CertificateUtil.cs#L69
        // https://blog.rassie.dk/2018/04/creating-an-x-509-certificate-chain-in-c/
        //


        var issuerSubjectKey = caCert.Extensions?["2.5.29.14"]!.RawData;
        var segment = new ArraySegment<byte>(issuerSubjectKey!, 2, issuerSubjectKey!.Length - 2);
        var authorityKeyIdentifier = new byte[segment.Count + 4];
        // these bytes define the "KeyID" part of the AuthorityKeyIdentifier
        authorityKeyIdentifier[0] = 0x30;
        authorityKeyIdentifier[1] = 0x16;
        authorityKeyIdentifier[2] = 0x80;
        authorityKeyIdentifier[3] = 0x14;
        segment.CopyTo(authorityKeyIdentifier, 4);
        intermediateReq.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
    }


    public static X509Extension MakeCdp(string url)
    {
        //
        // urls less than 119 char solution.
        // From Bartonjs of course.
        //
        // https://stackoverflow.com/questions/60742814/add-crl-distribution-points-cdp-extension-to-x509certificate2-certificate
        //
        // From Crypt32:  .NET doesn't support CDP extension. You have to use 3rd party libraries for that. BC is ok if it works for you.
        // Otherwise write you own. :)
        //

        byte[] encodedUrl = Encoding.ASCII.GetBytes(url);

        if (encodedUrl.Length > 119)
        {
            throw new NotSupportedException();
        }

        byte[] payload = new byte[encodedUrl.Length + 10];
        int offset = 0;
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 8);
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 6);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 4);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 2);
        payload[offset++] = 0x86;
        payload[offset++] = (byte)(encodedUrl.Length);
        Buffer.BlockCopy(encodedUrl, 0, payload, offset, encodedUrl.Length);

        return new X509Extension("2.5.29.31", payload, critical: false);
    }
}