

namespace Scan2PayUtility.data
{
    public class RequestHeader
    {
        /// <summary>
        /// 3rd-party payment provider ID
        /// </summary>
        public string Method { get; set; }

        /// <summary>
        /// Service Type
        /// </summary>
        public string ServiceType { get; set; }

        /// <summary>
        /// Merchant ID, provided by intella
        /// </summary>
        public string MchId { get; set; }

        /// <summary>
        /// Trade password, need to be SHA256 encoded, provided by intella
        /// </summary>
        public string TradeKey { get; set; }

        /// <summary>
        /// Time-stamp, format:yyyyMMddHHmmss
        /// </summary>
        public string CreateTime { get; set; }
    }
}
