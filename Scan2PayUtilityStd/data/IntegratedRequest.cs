
namespace Scan2PayUtility.data
{
    public class IntegratedRequest
    {

        /// <summary>
        /// Reuest string, AES encrypted
        /// </summary>
        public string Request { get; set; }

        /// <summary>
        /// ApiKey, RSA encrypted
        /// </summary>
        public string ApiKey { get; set; }

    }
}
