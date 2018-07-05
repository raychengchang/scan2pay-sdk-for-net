using System;
using System.Net;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Scan2PayUtility.data;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

namespace Scan2Pay
{
    public class Utility
    {

        public static readonly List<string> HeaderList = new List<string>() { "Method", "ServiceType", "MchId", "CreateTime", "TradeKey" };

        private static int DEFAULT_TIMEOUT = 60 * 1000;

        public static String doRequest(String url, String publicKey, String aesKey, String aesIV, Dictionary<string, string> requestMap)
        {
            string encryptRequest = getEncryptJson(publicKey, aesKey, aesIV, requestMap);
            string encryptResponse = doPost(url, encryptRequest);
            IntegratedResponse response = JsonConvert.DeserializeObject<IntegratedResponse>(encryptResponse);
            string decryptResponse = Aes128CBCDecrypt(response.Response, aesKey, aesIV);

            return decryptResponse;
        }

        private static String getEncryptJson(String publicKey, String aesKey, String aesIV, Dictionary<string, string> requestMap)
        {
            string json = JsonConvert.SerializeObject(requestMap);
            RequestHeader requesrHeader = JsonConvert.DeserializeObject<RequestHeader>(json);

            Dictionary<string, string> dataMap = new Dictionary<string, string>();
            foreach (string key in requestMap.Keys)
            {
                if (!HeaderList.Contains(key))
                {
                    dataMap.Add(key, requestMap[key]);
                }
            }

            RequestBody body = new RequestBody();
            body.Header = requesrHeader;
            body.Data = JsonConvert.SerializeObject(dataMap);

            string rJson = JsonConvert.SerializeObject(body);
            string encryptJson = Aes128CBCEncrypt(rJson, aesKey, aesIV);

            IntegratedRequest request = new IntegratedRequest();
            request.Request = encryptJson;

            string apiKey = RSAEncrypt(aesKey, publicKey);
            request.ApiKey = apiKey;

            return JsonConvert.SerializeObject(request);
        }

        /// <summary>
        /// POST
        /// </summary>
        /// <param name="url">url</param>
        /// <param name="parameters">parameters</param>
        private static String doPost(String url, String parameters)
        {
            return doPost(url, parameters, null, DEFAULT_TIMEOUT);
        }

        /// <summary>
        /// POST
        /// </summary>
        /// <param name="url"></param>
        /// <param name="parameters"></param>
        /// <param name="encode"></param>
        /// <returns></returns>
        private static String doPost(String url, String parameters, String encode)
        {
            return doPost(url, parameters, encode, DEFAULT_TIMEOUT);
        }

        /// <summary>
        /// POST
        /// </summary>
        /// <param name="url"></param>
        /// <param name="parameters"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        private static String doPost(String url, String parameters, int timeout)
        {
            return doPost(url, parameters, null, timeout);
        }

        /// <summary>
        /// POST
        /// </summary>
        /// <param name="url">url</param>
        /// <param name="parameters">parameters</param>
        /// <param name="timeout">timeout(m)</param>
        /// <returns></returns>
        private static String doPost(String url, String parameters, String encode, int timeout)
        {
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CheckValidationResult);

			var httpWebRequest = (HttpWebRequest)WebRequest.Create(url);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                streamWriter.Write(parameters);
                streamWriter.Flush();
                streamWriter.Close();
            }

            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                var result = streamReader.ReadToEnd();
                return result;
            }
        }

		public static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
		{
			return true;
		}

		private static string RSAEncrypt(string data, string publicKey)
        {
            Encoding encoding = Encoding.UTF8;

            //var csp = new RSACryptoServiceProvider(2048);
            //var pubKey = csp.ExportParameters(false);
            //var sr = new StringReader(publicKey);
            //we need a deserializer
            //var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //get the object back from the stream
            //pubKey = (RSAParameters)xs.Deserialize(sr);
            // csp = new RSACryptoServiceProvider();
            //csp.ImportParameters(pubKey);

            var csp = DecodeX509PublicKey(Convert.FromBase64String(publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "")));
            byte[] byte_encData = csp.Encrypt(encoding.GetBytes(data), false);

            //CryptoKey d = CryptoKey.FromPublicKey(publicKey, null);
            // OpenSSL.Crypto.RSA rsa = d.GetRSA();
            //byte[] byte_encData = rsa.PublicEncrypt(encoding.GetBytes(data), OpenSSL.Crypto.RSA.Padding.PKCS1);
            //rsa.Dispose();

            return Convert.ToBase64String(byte_encData);
        }


        public static string Md5(string value)
        {
            var original = Encoding.UTF8.GetBytes(value);
            var md5 = MD5.Create();
            var pwd = md5.ComputeHash(original);
            var sb = new StringBuilder();

            foreach (byte t in pwd)
            {
                sb.Append(t.ToString("x2"));
            }

            return sb.ToString();
        }

        private static string Sha256(string value)
        {
            SHA256 sha256 = SHA256Managed.Create();
            byte[] source = Encoding.UTF8.GetBytes(value);
            byte[] crypto = sha256.ComputeHash(source);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < crypto.Length; i++)
            {
                sb.Append(crypto[i].ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// AES128CBC Encryption
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Aes128CBCEncrypt(string plainText, string key, string iv)
        {
            RijndaelManaged AesEncryption = new RijndaelManaged();
            AesEncryption.KeySize = 128;
            AesEncryption.BlockSize = 128;
            AesEncryption.Mode = CipherMode.CBC;
            AesEncryption.Padding = PaddingMode.PKCS7;

            AesEncryption.IV = Encoding.UTF8.GetBytes(iv);
            AesEncryption.Key = Convert.FromBase64String(key);

            ICryptoTransform crypto = AesEncryption.CreateEncryptor();
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherText = crypto.TransformFinalBlock(data, 0, data.Length);
            return Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// AES 128 CBC Decryption
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Aes128CBCDecrypt(string cipherText, string key, string iv)
        {
            RijndaelManaged AesEncryption = new RijndaelManaged();
            AesEncryption.KeySize = 128;
            AesEncryption.BlockSize = 128;
            AesEncryption.Mode = CipherMode.CBC;
            AesEncryption.Padding = PaddingMode.PKCS7;

            AesEncryption.IV = Encoding.UTF8.GetBytes(iv);
            AesEncryption.Key = Convert.FromBase64String(key);

            ICryptoTransform decrypto = AesEncryption.CreateDecryptor();

            byte[] data = Convert.FromBase64String(cipherText);

            byte[] decryptedText = decrypto.TransformFinalBlock(data, 0, data.Length);

            return Encoding.UTF8.GetString(decryptedText);
        }

        public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];
            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            MemoryStream mem = new MemoryStream(x509key);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;

            try
            {

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;

                seq = binr.ReadBytes(15);       //read the Sequence OID
                if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8203)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;

                bt = binr.ReadByte();
                if (bt != 0x00)     //expect null byte next
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                byte lowbyte = 0x00;
                byte highbyte = 0x00;

                if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                    lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                else if (twobytes == 0x8202)
                {
                    highbyte = binr.ReadByte(); //advance 2 bytes
                    lowbyte = binr.ReadByte();
                }
                else
                    return null;
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                int modsize = BitConverter.ToInt32(modint, 0);

                byte firstbyte = binr.ReadByte();
                binr.BaseStream.Seek(-1, SeekOrigin.Current);

                if (firstbyte == 0x00)
                {   //if first byte (highest order) of modulus is zero, don't include it
                    binr.ReadByte();    //skip this null byte
                    modsize -= 1;   //reduce modulus buffer size by 1
                }

                byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                    return null;
                int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                byte[] exponent = binr.ReadBytes(expbytes);

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAKeyInfo = new RSAParameters();
                RSAKeyInfo.Modulus = modulus;
                RSAKeyInfo.Exponent = exponent;
                RSA.ImportParameters(RSAKeyInfo);
                return RSA;
            }
            catch (Exception)
            {
                return null;
            }

            finally { binr.Close(); }

        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
    }
}
