using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertificateCollection_teste
{
    class Program
    {
        static void Main(string[] args)
        {
            X509Certificate2 _X509Cert = new X509Certificate2();

            try
            {
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection collection1 = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, true);
                X509Certificate2Collection collection2 = (X509Certificate2Collection)collection.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, true);

                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(collection1, "Certificado(s) Digital(is) disponível(is)", "Selecione o Certificado Digital para uso no aplicativo", X509SelectionFlag.SingleSelection);

                foreach (X509Certificate2 x509 in scollection)
                {
                    try
                    {
                        byte[] rawdata = x509.RawData;
                        Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                        Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                        Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                        Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                        Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                        Console.WriteLine("Private Key: {0}{1}", x509.PrivateKey.ToXmlString(false), Environment.NewLine);
                        Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                        Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                        Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);

                        Console.WriteLine("Date inicio: {0}{1}", x509.NotBefore.ToShortDateString(), Environment.NewLine);
                        Console.WriteLine("Data vencimento: {0}{1}", x509.NotAfter.ToShortDateString(), Environment.NewLine);
                        X509Certificate2UI.DisplayCertificate(x509);
                        x509.Reset();
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("Information could not be written out for this certificate.");
                    }
                }

                Console.ReadKey();

                store.Close();
            }
            catch (Exception)
            {
                throw;
            }
        }

        public static X509Certificate2 FindFriendlyName(string nome)
        {
            X509Certificate2 _X509Cert = new X509Certificate2();

            try
            {
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection collection1 = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection collection2 = (X509Certificate2Collection)collection.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, false);

                if (nome == "")
                {
                    X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(collection2, "Certificado(s) Digital(is) disponível(is)", "Selecione o Certificado Digital para uso no aplicativo", X509SelectionFlag.SingleSelection);
                    if (scollection.Count == 0)
                    {
                        _X509Cert.Reset();
                        Console.WriteLine("Nenhum certificado escolhido", "Atenção");
                    }
                    else
                    {
                        _X509Cert = scollection[0];
                    }
                }
                else
                {
                    X509Certificate2Collection scollection = (X509Certificate2Collection)collection2.Find(X509FindType.FindBySubjectDistinguishedName, nome, false);
                    if (scollection.Count == 0)
                    {
                        Console.WriteLine("Nenhum certificado válido foi encontrado com o nome informado: " + nome, "Atenção");
                        _X509Cert.Reset();
                    }
                    else
                    {
                        _X509Cert = scollection[0];
                    }
                }
                store.Close();
                return _X509Cert;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return _X509Cert;
            }
        }
    }
}
