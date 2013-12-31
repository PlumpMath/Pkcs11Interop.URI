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

using System;
using System.Collections.Generic;
using System.Text;
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.URI
{
    public class Pkcs11UriBuilder
    {
        #region Constructors

        public Pkcs11UriBuilder()
            : this(true)
        {

        }

        public Pkcs11UriBuilder(bool checkLengths)
        {
            _checkLengths = checkLengths;
        }

        public Pkcs11UriBuilder(Pkcs11Uri pkcs11Uri)
        {
            if (pkcs11Uri == null)
                throw new ArgumentException("pkcs11Uri");

            ConstructFromPkcs11Uri(pkcs11Uri, pkcs11Uri.ChecksLengths);
        }

        public Pkcs11UriBuilder(Pkcs11Uri pkcs11Uri, bool checkLengths)
        {
            if (pkcs11Uri == null)
                throw new ArgumentException("pkcs11Uri");

            ConstructFromPkcs11Uri(pkcs11Uri, checkLengths);
        }

        private void ConstructFromPkcs11Uri(Pkcs11Uri pkcs11Uri, bool checkLengths)
        {
            if (pkcs11Uri == null)
                throw new ArgumentException("pkcs11Uri");

            _checkLengths = checkLengths;

            Token = pkcs11Uri.Token;
            Manufacturer = pkcs11Uri.Manufacturer;
            Serial = pkcs11Uri.Serial;
            Model = pkcs11Uri.Model;
            LibraryManufacturer = pkcs11Uri.LibraryManufacturer;
            LibraryDescription = pkcs11Uri.LibraryDescription;
            LibraryVersion = pkcs11Uri.LibraryVersion;
            Object = pkcs11Uri.Object;
            Type = pkcs11Uri.Type;
            Id = pkcs11Uri.Id;
            UnknownPathAttributes = pkcs11Uri.UnknownPathAttributes;

            PinSource = pkcs11Uri.PinSource;
            XPinValue = pkcs11Uri.XPinValue;
            XLibraryPath = pkcs11Uri.XLibraryPath;
            UnknownQueryAttributes = pkcs11Uri.UnknownQueryAttributes;
        }

        #endregion

        #region Properties and variables

        private bool _checkLengths = true;

        public bool ChecksLengths
        {
            get
            {
                return _checkLengths;
            }
        }

        #region Path attributes

        private string _tokenEncoded = null;

        private string _token = null;

        public string Token
        {
            get
            {
                return _token;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _token = value;
                    _tokenEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11Token;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    if ((_checkLengths == true) && (attributeValue.Length > Pkcs11UriSpec.Pk11TokenMaxLength))
                        throw new ArgumentOutOfRangeException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                    _tokenEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    _token = value;
                }
            }
        }

        private string _manufacturerEncoded = null;

        private string _manufacturer = null;

        public string Manufacturer
        {
            get
            {
                return _manufacturer;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _manufacturer = value;
                    _manufacturerEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11Manuf;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    if ((_checkLengths == true) && (attributeValue.Length > Pkcs11UriSpec.Pk11ManufMaxLength))
                        throw new ArgumentOutOfRangeException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                    _manufacturerEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    _manufacturer = value;
                }
            }
        }

        private string _serialEncoded = null;

        private string _serial = null;

        public string Serial
        {
            get
            {
                return _serial;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _serial = value;
                    _serialEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11Serial;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    if ((_checkLengths == true) && (attributeValue.Length > Pkcs11UriSpec.Pk11SerialMaxLength))
                        throw new ArgumentOutOfRangeException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                    _serialEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    _serial = value;
                }
            }
        }

        private string _modelEncoded = null;

        private string _model = null;

        public string Model
        {
            get
            {
                return _model;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _model = value;
                    _modelEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11Model;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    if ((_checkLengths == true) && (attributeValue.Length > Pkcs11UriSpec.Pk11ModelMaxLength))
                        throw new ArgumentOutOfRangeException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                    _modelEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    _model = value;
                }
            }
        }

        private string _libraryManufacturerEncoded = null;

        private string _libraryManufacturer = null;

        public string LibraryManufacturer
        {
            get
            {
                return _libraryManufacturer;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _libraryManufacturer = value;
                    _libraryManufacturerEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11LibManuf;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    if ((_checkLengths == true) && (attributeValue.Length > Pkcs11UriSpec.Pk11LibManufMaxLength))
                        throw new ArgumentOutOfRangeException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                    _libraryManufacturerEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    _libraryManufacturer = value;
                }
            }
        }

        private string _libraryDescriptionEncoded = null;

        private string _libraryDescription = null;

        public string LibraryDescription
        {
            get
            {
                return _libraryDescription;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _libraryDescription = value;
                    _libraryDescriptionEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11LibDesc;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    if ((_checkLengths == true) && (attributeValue.Length > Pkcs11UriSpec.Pk11LibDescMaxLength))
                        throw new ArgumentOutOfRangeException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                    _libraryDescriptionEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    _libraryDescription = value;
                }
            }
        }

        private string _libraryVersionEncoded = null;

        private string _libraryVersion = null;

        public string LibraryVersion
        {
            get
            {
                return _libraryVersion;
            }
            set
            {
                if (value == null)
                {
                    _libraryVersion = value;
                    _libraryVersionEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11LibVer;

                    if (value == string.Empty)
                        throw new Pkcs11UriException("Value of " + attributeName + " attribute cannot be empty");

                    int major = 0;
                    int minor = 0;

                    string[] parts = value.Split(new char[] { '.' }, StringSplitOptions.None);
                    if (parts.Length == 1)
                    {
                        major = Convert.ToInt32(parts[0]);
                    }
                    else if (parts.Length == 2)
                    {
                        if (string.IsNullOrEmpty(parts[0]))
                            throw new Pkcs11UriException("Attribute " + attributeName + " does not specify major version");

                        if (string.IsNullOrEmpty(parts[1]))
                            throw new Pkcs11UriException("Attribute " + attributeName + " does not specify minor version");

                        try
                        {
                            major = Convert.ToInt32(parts[0]);
                        }
                        catch (Exception ex)
                        {
                            throw new Pkcs11UriException("Attribute " + attributeName + " contains major version that cannot be converted to integer", ex);
                        }

                        try
                        {
                            minor = Convert.ToInt32(parts[1]);
                        }
                        catch (Exception ex)
                        {
                            throw new Pkcs11UriException("Attribute " + attributeName + " contains minor version that cannot be converted to integer", ex);
                        }
                    }
                    else
                    {
                        throw new Pkcs11UriException("Invalid value of " + attributeName + " attribute");
                    }

                    if ((_checkLengths == true) && ((major > 0xff) || (minor > 0xff)))
                        throw new ArgumentOutOfRangeException("Value of " + attributeName + " attribute exceeds the maximum allowed length");

                    _libraryVersion = value;
                    _libraryVersionEncoded = value;
                }
            }
        }

        private string _objectEncoded = null;

        private string _object = null;

        public string Object
        {
            get
            {
                return _object;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _object = value;
                    _objectEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11Object;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    _objectEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    _object = value;
                }
            }
        }

        private string _typeEncoded = null;

        private CKO? _type = null;

        public CKO? Type
        {
            get
            {
                return _type;
            }
            set
            {
                if (value == null)
                {
                    _type = value;
                    _typeEncoded = null;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11Type;

                    switch (value)
                    {
                        case CKO.CKO_PUBLIC_KEY:
                            _type = value;
                            _typeEncoded = Pkcs11UriSpec.Pk11TypePublic;
                            break;
                        case CKO.CKO_PRIVATE_KEY:
                            _type = value;
                            _typeEncoded = Pkcs11UriSpec.Pk11TypePrivate;
                            break;
                        case CKO.CKO_CERTIFICATE:
                            _type = value;
                            _typeEncoded = Pkcs11UriSpec.Pk11TypeCert;
                            break;
                        case CKO.CKO_SECRET_KEY:
                            _type = value;
                            _typeEncoded = Pkcs11UriSpec.Pk11TypeSecretKey;
                            break;
                        case CKO.CKO_DATA:
                            _type = value;
                            _typeEncoded = Pkcs11UriSpec.Pk11TypeData;
                            break;
                        default:
                            throw new Pkcs11UriException("Invalid value of " + attributeName + " attribute");
                    }
                }
            }
        }

        private string _idEncoded = null;

        private byte[] _id = null;

        public byte[] Id
        {
            get
            {
                return _id;
            }
            set
            {
                _id = value;
                _idEncoded = PctEncodeByteArray(value);
            }
        }

        private Dictionary<string, string> _unknownPathAttributes = null;

        public Dictionary<string, string> UnknownPathAttributes
        {
            get
            {
                return _unknownPathAttributes;
            }
            set
            {
                _unknownPathAttributes = value;
            }
        }

        private List<string> EncodeUnknownPathAttributes()
        {
            if (_unknownPathAttributes == null)
                return null;

            List<string> attributes = new List<string>();

            foreach (KeyValuePair<string, string> attribute in _unknownPathAttributes)
            {
                string attributeName = attribute.Key;
                string attributeValue = attribute.Value;

                // Validate attribute name
                if (string.IsNullOrEmpty(attributeName))
                    throw new Pkcs11UriException("Attribute name cannot be null or empty");

                if (!attributeName.StartsWith(Pkcs11UriSpec.Pk11PathVendorPrefix, StringComparison.InvariantCulture))
                    throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                if (attributeName.Length == Pkcs11UriSpec.Pk11PathVendorPrefix.Length)
                    throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                attributeName = EncodePk11String(null, attributeName, Pkcs11UriSpec.Pk11VendorAttrNameChars, false);

                // Validate attribute value
                if (string.IsNullOrEmpty(attributeValue))
                    attributeValue = string.Empty;
                else
                    attributeValue = EncodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);

                attributes.Add(attributeName + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + attributeValue);
            }

            return attributes;
        }

        #endregion

        #region Query attributes

        private string _pinSourceEncoded = null;

        private string _pinSource = null;

        public string PinSource
        {
            get
            {
                return _pinSource;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _pinSource = value;
                    _pinSourceEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11PinSource;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    _pinSourceEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                    _pinSource = value;
                }
            }
        }

        private string _xPinValueEncoded = null;

        private string _xPinValue = null;

        public string XPinValue
        {
            get
            {
                return _xPinValue;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _xPinValue = value;
                    _xPinValueEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11XPinValue;
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    _xPinValueEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                    _xPinValue = value;
                }
            }
        }

        private string _xLibraryPathEncoded = null;

        private string _xLibraryPath = null;

        public string XLibraryPath
        {
            get
            {
                return _xLibraryPath;
            }
            set
            {
                if (value == null)
                {
                    _xLibraryPath = value;
                    _xLibraryPathEncoded = value;
                }
                else
                {
                    string attributeName = Pkcs11UriSpec.Pk11XLibraryPath;

                    if (value == string.Empty)
                        throw new Pkcs11UriException("Value of " + attributeName + " attribute cannot be empty");
                    
                    byte[] attributeValue = ConvertUtils.Utf8StringToBytes(value);
                    _xLibraryPathEncoded = EncodePk11String(attributeName, value, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                    _xLibraryPath = value;
                }
            }
        }

        private Dictionary<string, List<string>> _unknownQueryAttributes = null;

        public Dictionary<string, List<string>> UnknownQueryAttributes
        {
            get
            {
                return _unknownQueryAttributes;
            }
            set
            {
                _unknownQueryAttributes = value;
            }
        }

        private List<string> EncodeUnknownQueryAttributes()
        {
            if (_unknownQueryAttributes == null)
                return null;

            List<string> attributes = new List<string>();

            foreach (KeyValuePair<string, List<string>> attribute in _unknownQueryAttributes)
            {
                string attributeName = attribute.Key;
                List<string> attributeValues = attribute.Value;

                // Validate attribute name
                if (string.IsNullOrEmpty(attributeName))
                    throw new Pkcs11UriException("Attribute name cannot be null or empty");

                if (!attributeName.StartsWith(Pkcs11UriSpec.Pk11QueryVendorPrefix, StringComparison.InvariantCulture))
                    throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                if (attributeName.Length == Pkcs11UriSpec.Pk11QueryVendorPrefix.Length)
                    throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                attributeName = EncodePk11String(null, attributeName, Pkcs11UriSpec.Pk11VendorAttrNameChars, false);

                // Validate attribute values
                if ((attributeValues == null) || (attributeValues.Count == 0))
                {
                    string value = string.Empty;
                    attributes.Add(attributeName + Pkcs11UriSpec.Pk11QueryAttributeNameAndValueSeparator + value);
                }
                else
                {
                    foreach (string attributeValue in attributeValues)
                    {
                        string value = string.Empty;

                        if (!string.IsNullOrEmpty(attributeValue))
                            value = EncodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);

                        attributes.Add(attributeName + Pkcs11UriSpec.Pk11QueryAttributeNameAndValueSeparator + value);
                    }
                }
            }

            return attributes;
        }

        #endregion

        #endregion

        public override string ToString()
        {
            List<string> pathAttributes = new List<string>();
            // Library definition
            if (_libraryManufacturerEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11LibManuf + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _libraryManufacturerEncoded);
            if (_libraryDescriptionEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11LibDesc + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _libraryDescriptionEncoded);
            if (_libraryVersionEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11LibVer + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _libraryVersionEncoded);
            // Token definition
            if (_manufacturerEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11Manuf + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _manufacturerEncoded);
            if (_modelEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11Model + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _modelEncoded);
            if (_serialEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11Serial + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _serialEncoded);
            if (_tokenEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11Token + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _tokenEncoded);
            // Object definition
            if (_typeEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11Type + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _typeEncoded);
            if (_objectEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11Object + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _objectEncoded);
            if (_idEncoded != null)
                pathAttributes.Add(Pkcs11UriSpec.Pk11Id + Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator + _idEncoded);
            // Vendor specific attributes
            if (_unknownPathAttributes != null)
                pathAttributes.AddRange(EncodeUnknownPathAttributes());

            List<string> queryAttributes = new List<string>();
            // Library definition
            if (_xLibraryPath != null)
                queryAttributes.Add(Pkcs11UriSpec.Pk11XLibraryPath + Pkcs11UriSpec.Pk11QueryAttributeNameAndValueSeparator + _xLibraryPathEncoded);
            // PIN handling definition
            if (_xPinValueEncoded != null)
                queryAttributes.Add(Pkcs11UriSpec.Pk11XPinValue + Pkcs11UriSpec.Pk11QueryAttributeNameAndValueSeparator + _xPinValueEncoded);
            if (_pinSourceEncoded != null)
                queryAttributes.Add(Pkcs11UriSpec.Pk11PinSource + Pkcs11UriSpec.Pk11QueryAttributeNameAndValueSeparator + _pinSourceEncoded);
            // Vendor specific attributes
            if (_unknownQueryAttributes != null)
                queryAttributes.AddRange(EncodeUnknownQueryAttributes());

            string path = string.Join(Pkcs11UriSpec.Pk11PathAttributesSeparator, pathAttributes.ToArray());
            string query = string.Join(Pkcs11UriSpec.Pk11QueryAttributesSeparator, queryAttributes.ToArray());
            
            string uri = Pkcs11UriSpec.Pk11UriSchemeName + Pkcs11UriSpec.Pk11UriAndPathSeparator;
            uri += (string.IsNullOrEmpty(path)) ? string.Empty : path;
            uri += (string.IsNullOrEmpty(query)) ? string.Empty : Pkcs11UriSpec.Pk11PathAndQuerySeparator + query;

            return uri;
        }

        public Pkcs11Uri ToPkcs11Uri()
        {
            return new Pkcs11Uri(ToString(), _checkLengths);
        }

        #region Private methods

        private string PctEncodeByteArray(byte[] byteArray)
        {
            if (byteArray == null)
                return null;

            StringBuilder stringBuilder = new StringBuilder(byteArray.Length * 3);

            for (int i = 0; i < byteArray.Length; i++)
            {
                stringBuilder.Append('%');
                stringBuilder.Append(BitConverter.ToString(new byte[] { byteArray[i] }));
            }

            return stringBuilder.ToString();
        }

        private string PctEncodeCharacter(char character)
        {
            byte[] bytes = UTF8Encoding.UTF8.GetBytes(new char[] { character });
            return PctEncodeByteArray(bytes);
        }

        private string EncodePk11String(string attributeName, string attributeValue, char[] allowedChars, bool usePctEncoding)
        {
            if (string.IsNullOrEmpty(attributeValue))
                return attributeValue;

            StringBuilder stringBuilder = new StringBuilder();

            for (int i = 0; i < attributeValue.Length; i++)
            {
                bool allowedChar = false;

                for (int j = 0; j < allowedChars.Length; j++)
                {
                    if (attributeValue[i] == allowedChars[j])
                    {
                        allowedChar = true;
                        break;
                    }
                }

                if (allowedChar)
                {
                    stringBuilder.Append(attributeValue[i]);
                }
                else
                {
                    if (usePctEncoding == true)
                    {
                        stringBuilder.Append(PctEncodeCharacter(attributeValue[i]));
                    }
                    else
                    {
                        if (attributeName != null)
                            throw new Pkcs11UriException("Value of " + attributeName + " attribute contains invalid character");
                        else
                            throw new Pkcs11UriException("Attribute name contains invalid character");
                    }
                }
            }

            return stringBuilder.ToString();
        }

        #endregion
    }
}
