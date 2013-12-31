/*
 *  Pkcs11Interop.URI - PKCS#11 URI extensions for Pkcs11Interop library
 *  Copyright (c) 2013-2014 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs11Interop.URI is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs11Interop.URI is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
 */

namespace Net.Pkcs11Interop.URI
{
    internal static class Pkcs11UriSpec
    {
        internal static readonly char[] Pk11PathAttrValueChars = null;

        internal static readonly char[] Pk11VendorAttrNameChars = null;

        internal static readonly char[] Pk11QueryAttrValueChars = null;

        internal const string Pk11UriSchemeName = "pkcs11";
        internal const string Pk11UriAndPathSeparator = ":";
        internal const string Pk11PathAttributesSeparator = ";";
        internal const string Pk11PathAttributeNameAndValueSeparator = "=";
        internal const string Pk11PathAndQuerySeparator = "?";
        internal const string Pk11QueryAttributesSeparator = "&";
        internal const string Pk11QueryAttributeNameAndValueSeparator = "=";

        internal const string Pk11Token = "token";
        internal const int Pk11TokenMaxLength = 32;
        internal const string Pk11Manuf = "manufacturer";
        internal const int Pk11ManufMaxLength = 32;
        internal const string Pk11Serial = "serial";
        internal const int Pk11SerialMaxLength = 16;
        internal const string Pk11Model = "model";
        internal const int Pk11ModelMaxLength = 16;
        internal const string Pk11LibManuf = "library-manufacturer";
        internal const int Pk11LibManufMaxLength = 32;
        internal const string Pk11LibDesc = "library-description";
        internal const int Pk11LibDescMaxLength = 32;
        internal const string Pk11LibVer = "library-version";
        internal const string Pk11Object = "object";
        internal const string Pk11Type = "type";
        internal const string Pk11Id = "id";
        internal const string Pk11PathVendorPrefix = "x-";

        internal const string Pk11TypePublic = "public";
        internal const string Pk11TypePrivate = "private";
        internal const string Pk11TypeCert = "cert";
        internal const string Pk11TypeSecretKey = "secret-key";
        internal const string Pk11TypeData = "data";

        internal const string Pk11PinSource = "pin-source";
        internal const string Pk11QueryVendorPrefix = "x-";
        internal const string Pk11XPinValue = "x-pin-value";
        internal const string Pk11XLibraryPath = "x-library-path";

        /// <summary>
        /// Class constructor
        /// </summary>
        static Pkcs11UriSpec()
        {
            Pk11PathAttrValueChars = new char[] {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // RFC 3986 unreserved
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // RFC 3986 unreserved
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // RFC 3986 unreserved
                '-', '.', '_', '~',  // RFC 3986 unreserved
                ':', '[', ']', '@', '!', '$', '\'', '(', ')', '*', '+', ',', '=', '&' // pk11-path-res-avail
                // pct-encoded are handled in parser
            };

            Pk11VendorAttrNameChars = new char[] {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // RFC 2234 ALPHA
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // RFC 2234 ALPHA
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // RFC 2234 DIGIT
                '-', '_' // pk11-x-attr-nm-char
            };

            Pk11QueryAttrValueChars = new char[] {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // RFC 3986 unreserved
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // RFC 3986 unreserved
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // RFC 3986 unreserved
                '-', '.', '_', '~',  // RFC 3986 unreserved
                ':', '[', ']', '@', '!', '$', '\'', '(', ')', '*', '+', ',', '=', '/', '?' // pk11-query-res-avail
                // pct-encoded are handled in parser
            };
        }
    }
}
