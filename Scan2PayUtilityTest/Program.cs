using Newtonsoft.Json;
using Scan2Pay;
using System;
using System.Collections.Generic;

namespace Scan2PayUtilityTest
{
	class Program
	{
		// please contact intella for the following required parameters
		// Scan2Pay API URL
		static string Scan2PayURL = "";
		// AES Key to encrypt request body. 
		// Generate a new AES key for evey transition is recommended.
		static string AESKey = "Y3UJ147HKIYRT8Ovrsik0A==";
		// AES Key IV, provided by intella
		static string AESiv = "";
		// Scan2Pay API server RSA public key
		static string publicKey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoBpQ54tk1chHugmV0VcT
....
-----END PUBLIC KEY-----";
		// Merchant ID
		static string MchId = "";
		// Trade key (password), need to be SHA256 hashed
		static string TradeKey = "";


		static void Main(string[] args)
		{
			// check required parameters
			if (Scan2PayURL.Length == 0 || publicKey.Length < 150 || AESKey.Length == 0 ||
				AESiv.Length == 0 || MchId.Length == 0 || TradeKey.Length == 0)
			{
				Debug("Fill required paramters in code!");
			}
			else
			{
				Debug("OLPay Test...");
				DoOLPayTest();
			}

			Debug("\nPress any key to exit.");
			Console.ReadLine();
		}

		static void Debug(String msg)
		{
			Console.ForegroundColor = ConsoleColor.Gray;
			Console.WriteLine(msg);
		}

		static void DoRequest(Dictionary<string, string> requestMap)
		{
			Debug("\nRequest:");
			string requestJson = JsonConvert.SerializeObject(requestMap);
			Debug(requestJson);

			Debug("\nResponse:");
			string responseJson = Utility.doRequest(Scan2PayURL, publicKey, AESKey, AESiv, requestMap);
			Debug(responseJson);
		}

		static void DoOLPayTest()
		{
			Dictionary<string, string> requestMap = new Dictionary<string, string>();

			// header
			requestMap.Add("Method", "00000");  // not specify payment provider
			requestMap.Add("ServiceType", "OLPay"); // MainSweep
			requestMap.Add("MchId", MchId);
			requestMap.Add("CreateTime", DateTime.Now.ToString("yyyyMMddHHmmss"));
			requestMap.Add("TradeKey", TradeKey);

			// data
			requestMap.Add("DeviceInfo", "skb0001");
			requestMap.Add("StoreorderNo", DateTime.Now.ToString("yyMMddHHmmss"));	// example: use time-stamp as order number
			requestMap.Add("Body", "Hot Meal");
			requestMap.Add("TotalFee", "100");

			DoRequest(requestMap);
		}
	}
}
