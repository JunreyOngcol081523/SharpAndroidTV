using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace AndroidTVAPI
{
    internal class CertificateUtils
    {
        public static string GenerateCertificate(
            string name,
            string country,
            string state,
            string locality,
            string organisation,
            string organisationUnit,
            string email,
            DateTime notBefore,
            DateTime notAfter,
            bool exClientAuth = true,
            int keyStrength = 2048,
            string signatureAlgorithm = "SHA256WITHRSA")
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private, random);

            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            var nameOids = new List<DerObjectIdentifier>
            {
                X509Name.CN,
                X509Name.O,
                X509Name.OU,
                X509Name.ST,
                X509Name.C,
                X509Name.L,
                X509Name.E
            };

            var nameValues = new Dictionary<DerObjectIdentifier, string>()
            {
                { X509Name.CN, name },
                { X509Name.O, organisation },
                { X509Name.OU, organisationUnit },
                { X509Name.ST, state },
                { X509Name.C, country },
                { X509Name.L, locality },
                { X509Name.E, email }
            };

            var subjectDN = new X509Name(nameOids, nameValues);
            var issuerDN = subjectDN;

            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);
            certificateGenerator.SetPublicKey(issuerKeyPair.Public);

            if (exClientAuth)
            {
                var keyUsage = new KeyUsage(KeyUsage.KeyEncipherment);
                certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, keyUsage.ToAsn1Object());

                // add client authentication extended key usage
                var extendedKeyUsage = new ExtendedKeyUsage(new[] { KeyPurposeID.id_kp_clientAuth });
                certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, extendedKeyUsage.ToAsn1Object());
            }

            // serial number is required, generate it randomly
            byte[] serial = new byte[20];
            random.NextBytes(serial);
            serial[0] = 1;
            certificateGenerator.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(serial));

            var certificate = certificateGenerator.Generate(signatureFactory);
            var privateKey = issuerKeyPair.Private;
            var pkcs8 = new Pkcs8Generator(privateKey);

            using (var textWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(textWriter))
                {
                    pemWriter.WriteObject(certificate);
                    pemWriter.WriteObject(pkcs8);
                }

                return textWriter.ToString();
            }
        }

        public static X509Certificate2 LoadCertificateFromPEM(string pem)
        {
            using (var textReader = new StringReader(pem))
            {
                using (Org.BouncyCastle.OpenSsl.PemReader reader = new Org.BouncyCastle.OpenSsl.PemReader(textReader))
                {
                    Org.BouncyCastle.Utilities.IO.Pem.PemObject read;
                    Org.BouncyCastle.X509.X509Certificate certificate = null;
                    AsymmetricKeyParameter privateKey = null;

                    while ((read = reader.ReadPemObject()) != null)
                    {
                        switch (read.Type)
                        {
                            case "CERTIFICATE":
                                {
                                    certificate = new Org.BouncyCastle.X509.X509Certificate(read.Content);
                                }
                                break;

                            case "PRIVATE KEY":
                                {
                                    privateKey = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(read.Content);
                                }
                                break;

                            default:
                                throw new NotSupportedException(read.Type);
                        }
                    }

                    if (certificate == null || privateKey == null)
                    {
                        throw new Exception("Unable to load certificate with the private key from the PEM!");
                    }

                    return GetX509CertificateWithPrivateKey(certificate, privateKey);
                }
            }
        }

        private static X509Certificate2 GetX509CertificateWithPrivateKey(
            Org.BouncyCastle.X509.X509Certificate bouncyCastleCert,
            AsymmetricKeyParameter privateKey)
        {
            // The original implementation round-tripped through a BouncyCastle PKCS#12 store,
            // which encrypts with RC2 by default. RC2 is not supported on Android, so instead
            // we load the certificate from its DER bytes and attach the RSA key directly.

            var cert = new X509Certificate2(bouncyCastleCert.GetEncoded());

            // Convert the BouncyCastle RSA private key to .NET RSA parameters
            var rsaKey = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)privateKey;
            var rsaParams = DotNetUtilities.ToRSAParameters(rsaKey);

            // Not disposed on purpose: the returned certificate keeps using this key.
            var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportParameters(rsaParams);

            var withKey = cert.CopyWithPrivateKey(rsa);

            try
            {
                // Re-export with .NET's own (modern) PKCS#12 encryption and reload. This makes
                // the certificate behave like a normally loaded one on Android's TLS stack.
                string password = Guid.NewGuid().ToString();
                byte[] pfx = withKey.Export(X509ContentType.Pfx, password);
                return new X509Certificate2(pfx, password, X509KeyStorageFlags.Exportable);
            }
            catch
            {
                // If the re-export isn't supported on this platform, use the cert as-is.
                return withKey;
            }
        }
    }
}
