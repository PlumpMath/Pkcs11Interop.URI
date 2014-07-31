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
using System.IO;
using System.Text;
using Net.Pkcs11Interop.Common;
using HLA = Net.Pkcs11Interop.HighLevelAPI;
using HLA4 = Net.Pkcs11Interop.HighLevelAPI4;
using HLA8 = Net.Pkcs11Interop.HighLevelAPI8;
using LLA4 = Net.Pkcs11Interop.LowLevelAPI4;
using LLA8 = Net.Pkcs11Interop.LowLevelAPI8;

namespace Net.Pkcs11Interop.URI
{
    /// <summary>
    /// PKCS#11 URI parser
    /// </summary>
    public class Pkcs11Uri
    {
        #region Constructors

        /// <summary>
        /// Intializes new instance of Pkcs11Uri class that parses provided PKCS#11 URI and checks max lengths of path attribute values
        /// </summary>
        /// <param name="uri">PKCS#11 URI to be parsed</param>
        public Pkcs11Uri(string uri)
            : this(uri, true)
        {

        }

        /// <summary>
        /// Intializes new instance of Pkcs11Uri class that parses provided PKCS#11 URI
        /// </summary>
        /// <param name="uri">PKCS#11 URI to be parsed</param>
        /// <param name="checkLengths">Flag indicating whether max lengths of path attribute values should be checked</param>
        public Pkcs11Uri(string uri, bool checkLengths)
        {
            if (string.IsNullOrEmpty(uri))
                throw new ArgumentNullException("uri");

            _checkLengths = checkLengths;

            Parse(Extract(uri));
        }

        #endregion

        #region Properties and variables

        /// <summary>
        /// Flag indicating whether max lengths of path attribute values were checked
        /// </summary>
        private bool _checkLengths = true;

        /// <summary>
        /// Flag indicating whether max lengths of path attribute values were checked
        /// </summary>
        public bool ChecksLengths
        {
            get
            {
                return _checkLengths;
            }
        }

        #region Flags
        
        /// <summary>
        /// Flag indicating whether PKCS#11 URI path attributes define specific PKCS#11 library
        /// </summary>
        public bool DefinesLibrary
        {
            get
            {
                return (LibraryManufacturer != null ||
                        LibraryDescription != null ||
                        LibraryVersion != null);
            }
        }

        /// <summary>
        /// Flag indicating whether PKCS#11 URI path attributes define specific token
        /// </summary>
        public bool DefinesToken
        {
            get
            {
                return (Token != null ||
                        Manufacturer != null ||
                        Serial != null ||
                        Model != null);
            }
        }

        /// <summary>
        /// Flag indicating whether PKCS#11 URI path attributes define specific object
        /// </summary>
        public bool DefinesObject
        {
            get
            {
                return (Object != null ||
                        Type != null ||
                        Id != null);
            }
        }

        #endregion

        #region Path attributes

        /// <summary>
        /// Value of path attribute "token" that corresponds to the "label" member of the CK_TOKEN_INFO structure
        /// </summary>
        private string _token = null;

        /// <summary>
        /// Value of path attribute "token" that corresponds to the "label" member of the CK_TOKEN_INFO structure
        /// </summary>
        public string Token
        {
            get
            {
                return _token;
            }
        }

        /// <summary>
        /// Value of path attribute "manufacturer" that corresponds to the "manufacturerID" member of CK_TOKEN_INFO structure
        /// </summary>
        private string _manufacturer = null;
        
        /// <summary>
        /// Value of path attribute "manufacturer" that corresponds to the "manufacturerID" member of CK_TOKEN_INFO structure
        /// </summary>
        public string Manufacturer
        {
            get
            {
                return _manufacturer;
            }
        }

        /// <summary>
        /// Value of path attribute "serial" that corresponds to the "serialNumber" member of CK_TOKEN_INFO structure
        /// </summary>
        private string _serial = null;

        /// <summary>
        /// Value of path attribute "serial" that corresponds to the "serialNumber" member of CK_TOKEN_INFO structure
        /// </summary>
        public string Serial
        {
            get
            {
                return _serial;
            }
        }

        /// <summary>
        /// Value of path attribute "model" that corresponds to the "model" member of CK_TOKEN_INFO structure
        /// </summary>
        private string _model = null;

        /// <summary>
        /// Value of path attribute "model" that corresponds to the "model" member of CK_TOKEN_INFO structure
        /// </summary>
        public string Model
        {
            get
            {
                return _model;
            }
        }

        /// <summary>
        /// Value of path attribute "library-manufacturer" that corresponds to the "manufacturerID" member of CK_INFO structure
        /// </summary>
        private string _libraryManufacturer = null;

        /// <summary>
        /// Value of path attribute "library-manufacturer" that corresponds to the "manufacturerID" member of CK_INFO structure
        /// </summary>
        public string LibraryManufacturer
        {
            get
            {
                return _libraryManufacturer;
            }
        }

        /// <summary>
        /// Value of path attribute "library-description" that corresponds to the "libraryDescription" member of CK_INFO structure
        /// </summary>
        private string _libraryDescription = null;

        /// <summary>
        /// Value of path attribute "library-description" that corresponds to the "libraryDescription" member of CK_INFO structure
        /// </summary>
        public string LibraryDescription
        {
            get
            {
                return _libraryDescription;
            }
        }

        /// <summary>
        /// Value of path attribute "library-version" that corresponds to the "libraryVersion" member of CK_INFO structure
        /// </summary>
        private string _libraryVersion = null;

        /// <summary>
        /// Value of path attribute "library-version" that corresponds to the "libraryVersion" member of CK_INFO structure
        /// </summary>
        public string LibraryVersion
        {
            get
            {
                return _libraryVersion;
            }
        }

        /// <summary>
        /// Value of path attribute "object" that corresponds to the "CKA_LABEL" object attribute
        /// </summary>
        private string _object = null;

        /// <summary>
        /// Value of path attribute "object" that corresponds to the "CKA_LABEL" object attribute
        /// </summary>
        public string Object
        {
            get
            {
                return _object;
            }
        }

        /// <summary>
        /// Value of path attribute "type" that corresponds to the "CKA_CLASS" object attribute
        /// </summary>
        private CKO? _type = null;

        /// <summary>
        /// Value of path attribute "type" that corresponds to the "CKA_CLASS" object attribute
        /// </summary>
        public CKO? Type
        {
            get
            {
                return _type;
            }
        }

        /// <summary>
        /// Value of path attribute "id" that corresponds to the "CKA_ID" object attribute
        /// </summary>
        private byte[] _id = null;

        /// <summary>
        /// Value of path attribute "id" that corresponds to the "CKA_ID" object attribute
        /// </summary>
        public byte[] Id
        {
            get
            {
                return _id;
            }
        }

        /// <summary>
        /// Collection of unknown vendor specific path attributes
        /// </summary>
        private Dictionary<string, string> _unknownPathAttributes = null;

        /// <summary>
        /// Collection of unknown vendor specific path attributes
        /// </summary>
        public Dictionary<string, string> UnknownPathAttributes
        {
            get
            {
                return _unknownPathAttributes;
            }
        }

        #region GetObjectAttributes

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public void GetObjectAttributes(out List<HLA.ObjectAttribute> objectAttributes)
        {
            List<HLA.ObjectAttribute> attributes = null;

            if (DefinesObject)
            {
                attributes = new List<HLA.ObjectAttribute>();
                if (Type != null)
                    attributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, Type.Value));
                if (Object != null)
                    attributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, Object));
                if (Id != null)
                    attributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, Id));
            }

            objectAttributes = attributes;
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public void GetObjectAttributes(out List<HLA8.ObjectAttribute> objectAttributes)
        {
            List<HLA8.ObjectAttribute> attributes = null;

            if (DefinesObject)
            {
                attributes = new List<HLA8.ObjectAttribute>();
                if (Type != null)
                    attributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, Type.Value));
                if (Object != null)
                    attributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, Object));
                if (Id != null)
                    attributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, Id));
            }

            objectAttributes = attributes;
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public void GetObjectAttributes(out List<HLA4.ObjectAttribute> objectAttributes)
        {
            List<HLA4.ObjectAttribute> attributes = null;

            if (DefinesObject)
            {
                attributes = new List<HLA4.ObjectAttribute>();
                if (Type != null)
                    attributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, Type.Value));
                if (Object != null)
                    attributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, Object));
                if (Id != null)
                    attributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, Id));
            }

            objectAttributes = attributes;
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public void GetObjectAttributes(out LLA8.CK_ATTRIBUTE[] objectAttributes)
        {
            List<LLA8.CK_ATTRIBUTE> attributes = null;

            if (DefinesObject)
            {
                attributes = new List<LLA8.CK_ATTRIBUTE>();
                if (Type != null)
                    attributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, Type.Value));
                if (Object != null)
                    attributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, Object));
                if (Id != null)
                    attributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, Id));
            }

            objectAttributes = attributes.ToArray();
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public void GetObjectAttributes(out LLA4.CK_ATTRIBUTE[] objectAttributes)
        {
            List<LLA4.CK_ATTRIBUTE> attributes = null;

            if (DefinesObject)
            {
                attributes = new List<LLA4.CK_ATTRIBUTE>();
                if (Type != null)
                    attributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, Type.Value));
                if (Object != null)
                    attributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, Object));
                if (Id != null)
                    attributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, Id));
            }

            objectAttributes = attributes.ToArray();
        }

        #endregion

        #endregion

        #region Query attributes

        /// <summary>
        /// Value of query attribute "pin-source" that specifies where token PIN can be obtained
        /// </summary>
        private string _pinSource = null;

        /// <summary>
        /// Value of query attribute "pin-source" that specifies where token PIN can be obtained
        /// </summary>
        public string PinSource
        {
            get
            {
                return _pinSource;
            }
        }

        /// <summary>
        /// Value of query attribute "pin-value" that contains token PIN
        /// </summary>
        private string _pinValue = null;

        /// <summary>
        /// Value of query attribute "pin-value" that contains token PIN
        /// </summary>
        public string PinValue
        {
            get
            {
                return _pinValue;
            }
        }

        /// <summary>
        /// Value of query attribute "module-name" that specifies name of the PKCS#11 library
        /// </summary>
        private string _moduleName = null;

        /// <summary>
        /// Value of query attribute "module-name" that specifies name of the PKCS#11 library
        /// </summary>
        public string ModuleName
        {
            get
            {
                return _moduleName;
            }
        }

        /// <summary>
        /// Value of query attribute "module-path" that specifies path to the PKCS#11 library
        /// </summary>
        private string _modulePath = null;

        /// <summary>
        /// Value of query attribute "module-path" that specifies path to the PKCS#11 library
        /// </summary>
        public string ModulePath
        {
            get
            {
                return _modulePath;
            }
        }

        /// <summary>
        /// Collection of unknown vendor specific query attributes
        /// </summary>
        private Dictionary<string, List<string>> _unknownQueryAttributes = null;

        /// <summary>
        /// Collection of unknown vendor specific query attributes
        /// </summary>
        public Dictionary<string, List<string>> UnknownQueryAttributes
        {
            get
            {
                return _unknownQueryAttributes;
            }
        }

        #endregion

        #endregion

        #region Matching methods

        #region LibraryInfo

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="manufacturer">PKCS#11 library manufacturer</param>
        /// <param name="description">PKCS#11 library description</param>
        /// <param name="version">PKCS#11 library version</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        private bool Matches(string manufacturer, string description, string version)
        {
            if (_unknownPathAttributes != null)
                return false;

            if (!SimpleStringsMatch(LibraryManufacturer, manufacturer))
                return false;

            if (!SimpleStringsMatch(LibraryDescription, description))
                return false;

            if (!SimpleStringsMatch(LibraryVersion, version))
                return false;

            return true;
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public bool Matches(HLA.LibraryInfo libraryInfo)
        {
            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public bool Matches(HLA8.LibraryInfo libraryInfo)
        {
            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public bool Matches(HLA4.LibraryInfo libraryInfo)
        {
            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public bool Matches(LLA8.CK_INFO libraryInfo)
        {
            string manufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
            string version = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);

            return Matches(manufacturer, description, version);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public bool Matches(LLA4.CK_INFO libraryInfo)
        {
            string manufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
            string version = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);

            return Matches(manufacturer, description, version);
        }

        #endregion

        #region TokenInfo

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="token">Token label</param>
        /// <param name="manufacturer">Token manufacturer</param>
        /// <param name="serial">Token serial number</param>
        /// <param name="model">Token model</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        private bool Matches(string token, string manufacturer, string serial, string model)
        {
            if (_unknownPathAttributes != null)
                return false;

            if (!SimpleStringsMatch(Token, token))
                return false;

            if (!SimpleStringsMatch(Manufacturer, manufacturer))
                return false;

            if (!SimpleStringsMatch(Serial, serial))
                return false;

            if (!SimpleStringsMatch(Model, model))
                return false;

            return true;
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public bool Matches(HLA.TokenInfo tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public bool Matches(HLA8.TokenInfo tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public bool Matches(HLA4.TokenInfo tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public bool Matches(LLA8.CK_TOKEN_INFO tokenInfo)
        {
            string token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
            string manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
            string serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
            string model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);

            return Matches(token, manufacturer, serial, model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public bool Matches(LLA4.CK_TOKEN_INFO tokenInfo)
        {
            string token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
            string manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
            string serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
            string model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);

            return Matches(token, manufacturer, serial, model);
        }

        #endregion

        #region ObjectAttributes

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="ckaClass">Value of CKA_CLASS object attribute</param>
        /// <param name="ckaLabel">Value of CKA_LABEL object attribute</param>
        /// <param name="ckaId">Value of CKA_ID object attribute</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        private bool Matches(CKO? ckaClass, string ckaLabel, byte[] ckaId)
        {
            if (_unknownPathAttributes != null)
                return false;

            if (!ObjectTypesMatch(Type, ckaClass))
                return false;

            if (!SimpleStringsMatch(Object, ckaLabel))
                return false;

            if (!ByteArraysMatch(Id, ckaId))
                return false;

            return true;
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public bool Matches(List<HLA.ObjectAttribute> objectAttributes)
        {
            if (objectAttributes == null)
                throw new ArgumentNullException("objectAttributes");

            ulong ckaClassType = Convert.ToUInt64(CKA.CKA_CLASS);
            CKO? ckaClassValue = null;
            bool ckaClassFound = false;

            ulong ckaLabelType = Convert.ToUInt64(CKA.CKA_LABEL);
            string ckaLabelValue = null;
            bool ckaLabelFound = false;

            ulong ckaIdType = Convert.ToUInt64(CKA.CKA_ID);
            byte[] ckaIdValue = null;
            bool ckaIdFound = false;

            foreach (HLA.ObjectAttribute objectAttribute in objectAttributes)
            {
                if (objectAttribute == null)
                    continue;

                if (objectAttribute.Type == ckaClassType)
                {
                    ckaClassValue = (CKO)Convert.ToUInt32(objectAttribute.GetValueAsUlong());
                    ckaClassFound = true;
                }
                else if (objectAttribute.Type == ckaLabelType)
                {
                    ckaLabelValue = objectAttribute.GetValueAsString();
                    ckaLabelFound = true;
                }
                else if (objectAttribute.Type == ckaIdType)
                {
                    ckaIdValue = objectAttribute.GetValueAsByteArray();
                    ckaIdFound = true;
                }

                if (ckaClassFound && ckaLabelFound && ckaIdFound)
                    break;
            }

            if ((!ckaClassFound) && (Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public bool Matches(List<HLA8.ObjectAttribute> objectAttributes)
        {
            if (objectAttributes == null)
                throw new ArgumentNullException("objectAttributes");

            ulong ckaClassType = Convert.ToUInt64(CKA.CKA_CLASS);
            CKO? ckaClassValue = null;
            bool ckaClassFound = false;

            ulong ckaLabelType = Convert.ToUInt64(CKA.CKA_LABEL);
            string ckaLabelValue = null;
            bool ckaLabelFound = false;

            ulong ckaIdType = Convert.ToUInt64(CKA.CKA_ID);
            byte[] ckaIdValue = null;
            bool ckaIdFound = false;

            foreach (HLA8.ObjectAttribute objectAttribute in objectAttributes)
            {
                if (objectAttribute == null)
                    continue;

                if (objectAttribute.Type == ckaClassType)
                {
                    ckaClassValue = (CKO)Convert.ToUInt32(objectAttribute.GetValueAsUlong());
                    ckaClassFound = true;
                }
                else if (objectAttribute.Type == ckaLabelType)
                {
                    ckaLabelValue = objectAttribute.GetValueAsString();
                    ckaLabelFound = true;
                }
                else if (objectAttribute.Type == ckaIdType)
                {
                    ckaIdValue = objectAttribute.GetValueAsByteArray();
                    ckaIdFound = true;
                }

                if (ckaClassFound && ckaLabelFound && ckaIdFound)
                    break;
            }

            if ((!ckaClassFound) && (Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public bool Matches(List<HLA4.ObjectAttribute> objectAttributes)
        {
            if (objectAttributes == null)
                throw new ArgumentNullException("objectAttributes");

            uint ckaClassType = (uint) CKA.CKA_CLASS;
            CKO? ckaClassValue = null;
            bool ckaClassFound = false;

            uint ckaLabelType = (uint) CKA.CKA_LABEL;
            string ckaLabelValue = null;
            bool ckaLabelFound = false;

            uint ckaIdType = (uint) CKA.CKA_ID;
            byte[] ckaIdValue = null;
            bool ckaIdFound = false;

            foreach (HLA4.ObjectAttribute objectAttribute in objectAttributes)
            {
                if (objectAttribute == null)
                    continue;

                if (objectAttribute.Type == ckaClassType)
                {
                    ckaClassValue = (CKO) objectAttribute.GetValueAsUint();
                    ckaClassFound = true;
                }
                else if (objectAttribute.Type == ckaLabelType)
                {
                    ckaLabelValue = objectAttribute.GetValueAsString();
                    ckaLabelFound = true;
                }
                else if (objectAttribute.Type == ckaIdType)
                {
                    ckaIdValue = objectAttribute.GetValueAsByteArray();
                    ckaIdFound = true;
                }

                if (ckaClassFound && ckaLabelFound && ckaIdFound)
                    break;
            }

            if ((!ckaClassFound) && (Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public bool Matches(List<LLA8.CK_ATTRIBUTE> objectAttributes)
        {
            if (objectAttributes == null)
                throw new ArgumentNullException("objectAttributes");

            uint ckaClassType = (uint)CKA.CKA_CLASS;
            CKO? ckaClassValue = null;
            bool ckaClassFound = false;

            uint ckaLabelType = (uint)CKA.CKA_LABEL;
            string ckaLabelValue = null;
            bool ckaLabelFound = false;

            uint ckaIdType = (uint)CKA.CKA_ID;
            byte[] ckaIdValue = null;
            bool ckaIdFound = false;

            foreach (LLA8.CK_ATTRIBUTE objectAttribute in objectAttributes)
            {
                LLA8.CK_ATTRIBUTE attribute = objectAttribute;

                if (attribute.type == ckaClassType)
                {
                    ulong ulongValue = 0;
                    LLA8.CkaUtils.ConvertValue(ref attribute, out ulongValue);
                    ckaClassValue = (CKO)Convert.ToUInt32(ulongValue);
                    ckaClassFound = true;
                }
                else if (attribute.type == ckaLabelType)
                {
                    LLA8.CkaUtils.ConvertValue(ref attribute, out ckaLabelValue);
                    ckaLabelFound = true;
                }
                else if (objectAttribute.type == ckaIdType)
                {
                    LLA8.CkaUtils.ConvertValue(ref attribute, out ckaIdValue);
                    ckaIdFound = true;
                }

                if (ckaClassFound && ckaLabelFound && ckaIdFound)
                    break;
            }

            if ((!ckaClassFound) && (Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public bool Matches(List<LLA4.CK_ATTRIBUTE> objectAttributes)
        {
            if (objectAttributes == null)
                throw new ArgumentNullException("objectAttributes");

            uint ckaClassType = (uint)CKA.CKA_CLASS;
            CKO? ckaClassValue = null;
            bool ckaClassFound = false;

            uint ckaLabelType = (uint)CKA.CKA_LABEL;
            string ckaLabelValue = null;
            bool ckaLabelFound = false;

            uint ckaIdType = (uint)CKA.CKA_ID;
            byte[] ckaIdValue = null;
            bool ckaIdFound = false;

            foreach (LLA4.CK_ATTRIBUTE objectAttribute in objectAttributes)
            {
                LLA4.CK_ATTRIBUTE attribute = objectAttribute;

                if (attribute.type == ckaClassType)
                {
                    uint uintValue = 0;
                    LLA4.CkaUtils.ConvertValue(ref attribute, out uintValue);
                    ckaClassValue = (CKO)uintValue;
                    ckaClassFound = true;
                }
                else if (attribute.type == ckaLabelType)
                {
                    LLA4.CkaUtils.ConvertValue(ref attribute, out ckaLabelValue);
                    ckaLabelFound = true;
                }
                else if (objectAttribute.type == ckaIdType)
                {
                    LLA4.CkaUtils.ConvertValue(ref attribute, out ckaIdValue);
                    ckaIdFound = true;
                }

                if (ckaClassFound && ckaLabelFound && ckaIdFound)
                    break;
            }

            if ((!ckaClassFound) && (Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        #endregion

        #region GetMatchingSlotList

        /// <summary>
        /// Obtains a list of all slots where token that matches PKCS#11 URI is present
        /// </summary>
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <returns>List of slots matching PKCS#11 URI</returns>
        public List<HLA.Slot> GetMatchingSlotList(HLA.Pkcs11 pkcs11)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<HLA.Slot> matchingSlots = new List<HLA.Slot>();

            HLA.LibraryInfo libraryInfo = pkcs11.GetInfo();
            if (!Matches(libraryInfo))
                return matchingSlots;

            List<HLA.Slot> slots = pkcs11.GetSlotList(true);
            if ((slots == null) || (slots.Count == 0))
                return slots;

            foreach (HLA.Slot slot in slots)
            {
                HLA.TokenInfo tokenInfo = slot.GetTokenInfo();
                if (Matches(tokenInfo))
                    matchingSlots.Add(slot);
            }

            return matchingSlots;
        }

        /// <summary>
        /// Obtains a list of all slots where token that matches PKCS#11 URI is present
        /// </summary>
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <returns>List of slots matching PKCS#11 URI</returns>
        public List<HLA8.Slot> GetMatchingSlotList(HLA8.Pkcs11 pkcs11)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<HLA8.Slot> matchingSlots = new List<HLA8.Slot>();

            HLA8.LibraryInfo libraryInfo = pkcs11.GetInfo();
            if (!Matches(libraryInfo))
                return matchingSlots;

            List<HLA8.Slot> slots = pkcs11.GetSlotList(true);
            if ((slots == null) || (slots.Count == 0))
                return slots;

            foreach (HLA8.Slot slot in slots)
            {
                HLA8.TokenInfo tokenInfo = slot.GetTokenInfo();
                if (Matches(tokenInfo))
                    matchingSlots.Add(slot);
            }

            return matchingSlots;
        }

        /// <summary>
        /// Obtains a list of all slots where token that matches PKCS#11 URI is present
        /// </summary>
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <returns>List of slots matching PKCS#11 URI</returns>
        public List<HLA4.Slot> GetMatchingSlotList(HLA4.Pkcs11 pkcs11)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<HLA4.Slot> matchingSlots = new List<HLA4.Slot>();

            HLA4.LibraryInfo libraryInfo = pkcs11.GetInfo();
            if (!Matches(libraryInfo))
                return matchingSlots;

            List<HLA4.Slot> slots = pkcs11.GetSlotList(true);
            if ((slots == null) || (slots.Count == 0))
                return slots;

            foreach (HLA4.Slot slot in slots)
            {
                HLA4.TokenInfo tokenInfo = slot.GetTokenInfo();
                if (Matches(tokenInfo))
                    matchingSlots.Add(slot);
            }

            return matchingSlots;
        }

        /// <summary>
        /// Obtains a list of all slots where token that matches PKCS#11 URI is present
        /// </summary>
        /// <param name="pkcs11">Low level PKCS#11 wrapper</param>
        /// <param name="slotList">List of slots matching PKCS#11 URI</param>
        /// <returns>CKR_OK if successful; any other value otherwise</returns>
        public CKR GetMatchingSlotList(LLA8.Pkcs11 pkcs11, out ulong[] slotList)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<ulong> matchingSlots = new List<ulong>();

            // Get library information
            LLA8.CK_INFO libraryInfo = new LLA8.CK_INFO();
            CKR rv = pkcs11.C_GetInfo(ref libraryInfo);
            if (rv != CKR.CKR_OK)
            {
                slotList = matchingSlots.ToArray();
                return rv;
            }

            // Check whether library matches URI
            if (!Matches(libraryInfo))
            {
                slotList = matchingSlots.ToArray();
                return CKR.CKR_OK;
            }

            // Get number of slots in first call
            ulong slotCount = 0;
            rv = pkcs11.C_GetSlotList(true, null, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = matchingSlots.ToArray();
                return rv;
            }

            if (slotCount < 1)
            {
                slotList = matchingSlots.ToArray();
                return CKR.CKR_OK;
            }

            // Allocate array for slot IDs
            ulong[] slots = new ulong[slotCount];

            // Get slot IDs in second call
            rv = pkcs11.C_GetSlotList(true, slots, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = matchingSlots.ToArray();
                return rv;
            }

            // Match slots with Pkcs11Uri
            foreach (ulong slot in slots)
            {
                LLA8.CK_TOKEN_INFO tokenInfo = new LLA8.CK_TOKEN_INFO();
                rv = pkcs11.C_GetTokenInfo(slot, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                {
                    slotList = matchingSlots.ToArray();
                    return rv;
                }

                if (Matches(tokenInfo))
                    matchingSlots.Add(slot);
            }

            slotList = matchingSlots.ToArray();
            return CKR.CKR_OK;
        }

        /// <summary>
        /// Obtains a list of all slots where token that matches PKCS#11 URI is present
        /// </summary>
        /// <param name="pkcs11">Low level PKCS#11 wrapper</param>
        /// <param name="slotList">List of slots matching PKCS#11 URI</param>
        /// <returns>CKR_OK if successful; any other value otherwise</returns>
        public CKR GetMatchingSlotList(LLA4.Pkcs11 pkcs11, out uint[] slotList)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<uint> matchingSlots = new List<uint>();

            // Get library information
            LLA4.CK_INFO libraryInfo = new LLA4.CK_INFO();
            CKR rv = pkcs11.C_GetInfo(ref libraryInfo);
            if (rv != CKR.CKR_OK)
            {
                slotList = matchingSlots.ToArray();
                return rv;
            }

            // Check whether library matches URI
            if (!Matches(libraryInfo))
            {
                slotList = matchingSlots.ToArray();
                return CKR.CKR_OK;
            }

            // Get number of slots in first call
            uint slotCount = 0;
            rv = pkcs11.C_GetSlotList(true, null, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = matchingSlots.ToArray();
                return rv;
            }

            if (slotCount < 1)
            {
                slotList = matchingSlots.ToArray();
                return CKR.CKR_OK;
            }

            // Allocate array for slot IDs
            uint[] slots = new uint[slotCount];

            // Get slot IDs in second call
            rv = pkcs11.C_GetSlotList(true, slots, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = matchingSlots.ToArray();
                return rv;
            }

            // Match slots with Pkcs11Uri
            foreach (uint slot in slots)
            {
                LLA4.CK_TOKEN_INFO tokenInfo = new LLA4.CK_TOKEN_INFO();
                rv = pkcs11.C_GetTokenInfo(slot, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                {
                    slotList = matchingSlots.ToArray();
                    return rv;
                }

                if (Matches(tokenInfo))
                    matchingSlots.Add(slot);
            }

            slotList = matchingSlots.ToArray();
            return CKR.CKR_OK;
        }

        #endregion

        #endregion

        #region Private methods

        /// <summary>
        /// Extracts PKCS#11 URI from text and removes all whitespaces
        /// </summary>
        /// <param name="text">Text that contains PKCS#11 URI</param>
        /// <returns>PKCS#11 URI without whitespaces</returns>
        private string Extract(string text)
        {
            if (string.IsNullOrEmpty(text))
                throw new ArgumentNullException("text");

            StringBuilder stringBuilder = new StringBuilder(text.Length);
            for (int i = 0; i < text.Length; i++)
                if (!char.IsWhiteSpace(text[i]))
                    stringBuilder.Append(text[i]);

            string uri = stringBuilder.ToString();

            int firstCharPosition = 0;
            int lastCharPosition = 0;

            firstCharPosition = uri.IndexOf(Pkcs11UriSpec.Pk11UriSchemeName + Pkcs11UriSpec.Pk11UriAndPathSeparator, StringComparison.InvariantCulture);
            if (firstCharPosition > 0)
            {
                if (uri[firstCharPosition - 1] == '"')
                {
                    uri = uri.Remove(0, firstCharPosition);
                    lastCharPosition = uri.IndexOf('"');
                }
                else if (uri[firstCharPosition - 1] == '<')
                {
                    uri = uri.Remove(0, firstCharPosition);
                    lastCharPosition = uri.IndexOf('>');
                }
                else
                    throw new Pkcs11UriException("URI is not delimited within double quotes or angle brackets");

                if (lastCharPosition < 0)
                    throw new Pkcs11UriException("URI is not correctly delimited within double quotes or angle brackets");

                uri = uri.Substring(0, lastCharPosition);
            }

            return uri;
        }

        /// <summary>
        /// Parses PKCS#11 URI
        /// </summary>
        /// <param name="uri">PKCS#11 URI that should be parsed</param>
        private void Parse(string uri)
        {
            if (string.IsNullOrEmpty(uri))
                throw new ArgumentNullException("uri");

            // Check URI scheme
            if (!uri.StartsWith(Pkcs11UriSpec.Pk11UriSchemeName + Pkcs11UriSpec.Pk11UriAndPathSeparator, StringComparison.InvariantCulture))
                throw new Pkcs11UriException("Unknown URI scheme name");

            // Remove URI prefix
            uri = uri.Remove(0, Pkcs11UriSpec.Pk11UriSchemeName.Length + Pkcs11UriSpec.Pk11UriAndPathSeparator.Length);

            // Empty PKCS#11 URI is also valid
            if (uri == string.Empty)
                return;

            // Extract path and query parts
            string[] parts = uri.Split(new string[] { Pkcs11UriSpec.Pk11PathAndQuerySeparator }, 2, StringSplitOptions.None);
            string path = parts[0];
            string query = (parts.Length == 2) ? parts[1] : string.Empty;

            if ((parts.Length == 2) && (string.IsNullOrEmpty(parts[1])))
                throw new Pkcs11UriException("Question mark is present in the URI but query component is missing");

            // Parse path attributes
            if (!string.IsNullOrEmpty(path))
            {
                string[] pathAttributes = path.Split(new string[] { Pkcs11UriSpec.Pk11PathAttributesSeparator }, StringSplitOptions.None);
                foreach (string pathAttribute in pathAttributes)
                    ParsePathAttribute(pathAttribute);
            }

            // Parse query attributes
            if (!string.IsNullOrEmpty(query))
            {
                string[] queryAttributes = query.Split(new string[] { Pkcs11UriSpec.Pk11QueryAttributesSeparator }, StringSplitOptions.None);
                foreach (string queryAttribute in queryAttributes)
                    ParseQueryAttribute(queryAttribute);
            }
        }

        /// <summary>
        /// Parses path attribute
        /// </summary>
        /// <param name="attribute">Path attribute that should be parsed</param>
        private void ParsePathAttribute(string attribute)
        {
            string[] parts = attribute.Split(new string[] { Pkcs11UriSpec.Pk11PathAttributeNameAndValueSeparator }, 2, StringSplitOptions.None);
            if (parts.Length < 2)
                throw new Pkcs11UriException("Attribute name and value are not separated by an equals sign");

            string attributeName = parts[0];
            string attributeValue = parts[1];

            switch (attributeName)
            {
                case Pkcs11UriSpec.Pk11Token:

                    if (_token != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        if ((_checkLengths == true) && (bytes.Length > Pkcs11UriSpec.Pk11TokenMaxLength))
                            throw new Pkcs11UriException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                        _token = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _token = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11Manuf:

                    if (_manufacturer != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        if ((_checkLengths == true) && (bytes.Length > Pkcs11UriSpec.Pk11ManufMaxLength))
                            throw new Pkcs11UriException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                        _manufacturer = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _manufacturer = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11Serial:

                    if (_serial != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        if ((_checkLengths == true) && (bytes.Length > Pkcs11UriSpec.Pk11SerialMaxLength))
                            throw new Pkcs11UriException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                        _serial = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _serial = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11Model:

                    if (_model != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        if ((_checkLengths == true) && (bytes.Length > Pkcs11UriSpec.Pk11ModelMaxLength))
                            throw new Pkcs11UriException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                        _model = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _model = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11LibManuf:

                    if (_libraryManufacturer != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        if ((_checkLengths == true) && (bytes.Length > Pkcs11UriSpec.Pk11LibManufMaxLength))
                            throw new Pkcs11UriException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                        _libraryManufacturer = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _libraryManufacturer = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11LibDesc:

                    if (_libraryDescription != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        if ((_checkLengths == true) && (bytes.Length > Pkcs11UriSpec.Pk11LibDescMaxLength))
                            throw new Pkcs11UriException("Value of " + attributeName + " attribute exceeds the maximum allowed length");
                        _libraryDescription = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _libraryDescription = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11Object:

                    if (_object != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        _object = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _object = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11Id:

                    if (_id != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue != string.Empty)
                    {
                        _id = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                    }
                    else
                    {
                        _id = new byte[0];
                    }

                    break;

                case Pkcs11UriSpec.Pk11LibVer:

                    if (_libraryVersion != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue == string.Empty)
                        throw new Pkcs11UriException("Value of " + attributeName + " attribute cannot be empty");

                    int major = 0;
                    int minor = 0;

                    parts = attributeValue.Split(new char[] { '.' }, StringSplitOptions.None);
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
                        throw new Pkcs11UriException("Value of " + attributeName + " attribute exceeds the maximum allowed length");

                    _libraryVersion = string.Format("{0}.{1}", major, minor);
    
                    break;

                case Pkcs11UriSpec.Pk11Type:

                    if (_type != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");

                    if (attributeValue == string.Empty)
                        throw new Pkcs11UriException("Value of " + attributeName + " attribute cannot be empty");

                    switch (attributeValue)
                    {
                        case Pkcs11UriSpec.Pk11TypePublic:
                            _type = CKO.CKO_PUBLIC_KEY;
                            break;
                        case Pkcs11UriSpec.Pk11TypePrivate:
                            _type = CKO.CKO_PRIVATE_KEY;
                            break;
                        case Pkcs11UriSpec.Pk11TypeCert:
                            _type = CKO.CKO_CERTIFICATE;
                            break;
                        case Pkcs11UriSpec.Pk11TypeSecretKey:
                            _type = CKO.CKO_SECRET_KEY;
                            break;
                        case Pkcs11UriSpec.Pk11TypeData:
                            _type = CKO.CKO_DATA;
                            break;
                        default:
                            throw new Pkcs11UriException("Invalid value of " + attributeName + " attribute");
                    }

                    break;

                default:

                    if (!attributeName.StartsWith(Pkcs11UriSpec.Pk11PathVendorPrefix, StringComparison.InvariantCulture))
                        throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                    if (attributeName.Length == Pkcs11UriSpec.Pk11PathVendorPrefix.Length)
                        throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                    byte[] vendorAttrName = DecodePk11String(null, attributeName, Pkcs11UriSpec.Pk11VendorAttrNameChars, false);
                    attributeName = ConvertUtils.BytesToUtf8String(vendorAttrName);

                    if (attributeValue != string.Empty)
                    {
                        byte[] vendorAttrValue = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11PathAttrValueChars, true);
                        attributeValue = ConvertUtils.BytesToUtf8String(vendorAttrValue);
                    }

                    if (_unknownPathAttributes == null)
                        _unknownPathAttributes = new Dictionary<string, string>();

                    if (_unknownPathAttributes.ContainsKey(attributeName))
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the path component");
                    else
                        _unknownPathAttributes.Add(attributeName, attributeValue);

                    break;
            }
        }

        /// <summary>
        /// Parses query attribute
        /// </summary>
        /// <param name="attribute">Query attribute that should be parsed</param>
        private void ParseQueryAttribute(string attribute)
        {
            string[] parts = attribute.Split(new string[] { Pkcs11UriSpec.Pk11QueryAttributeNameAndValueSeparator }, 2, StringSplitOptions.None);
            if (parts.Length < 2)
                throw new Pkcs11UriException("Attribute name and value are not separated by an equals sign");

            string attributeName = parts[0];
            string attributeValue = parts[1];

            switch (attributeName)
            {
                case Pkcs11UriSpec.Pk11PinSource:

                    if (_pinSource != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the query component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                        _pinSource = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _pinSource = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11PinValue:

                    if (_pinValue != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the query component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                        _pinValue = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _pinValue = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11ModuleName:

                    if (_moduleName != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the query component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                        _moduleName = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _moduleName = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11ModulePath:

                    if (_modulePath != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the query component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                        _modulePath = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _modulePath = string.Empty;
                    }

                    break;

                default:

                    if (!attributeName.StartsWith(Pkcs11UriSpec.Pk11QueryVendorPrefix, StringComparison.InvariantCulture))
                        throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                    if (attributeName.Length == Pkcs11UriSpec.Pk11QueryVendorPrefix.Length)
                        throw new Pkcs11UriException("Invalid attribute name: " + attributeName);

                    byte[] vendorAttrName = DecodePk11String(null, attributeName, Pkcs11UriSpec.Pk11VendorAttrNameChars, false);
                    attributeName = ConvertUtils.BytesToUtf8String(vendorAttrName);

                    if (attributeValue != string.Empty)
                    {
                        byte[] vendorAttrValue = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                        attributeValue = ConvertUtils.BytesToUtf8String(vendorAttrValue);
                    }

                    if (_unknownQueryAttributes == null)
                        _unknownQueryAttributes = new Dictionary<string, List<string>>();

                    if (_unknownQueryAttributes.ContainsKey(attributeName))
                        _unknownQueryAttributes[attributeName].Add(attributeValue);
                    else
                        _unknownQueryAttributes.Add(attributeName, new List<string>() { attributeValue });

                    break;
            }
        }

        /// <summary>
        /// Checks whether Pk11String contains invalid characters and optionaly decodes percent encoded characters
        /// </summary>
        /// <param name="attributeName">Name of attribute whose value is being decoded</param>
        /// <param name="pk11String">Pk11String that should be decoded</param>
        /// <param name="allowedChars">Characters allowed to be present unencoded in Pk11String</param>
        /// <param name="decodePctEncodedChars">Flag indicating whether percent encoded characters should be decoded</param>
        /// <returns>Decoded Pk11String</returns>
        private byte[] DecodePk11String(string attributeName, string pk11String, char[] allowedChars, bool decodePctEncodedChars)
        {
            if (string.IsNullOrEmpty(pk11String))
                return null;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                int i = 0;

                while (i < pk11String.Length)
                {
                    if (decodePctEncodedChars)
                    {
                        if (pk11String[i] == '%')
                        {
                            if ((i + 2) > pk11String.Length)
                            {
                                if (attributeName != null)
                                    throw new Pkcs11UriException("Value of " + attributeName + " attribute contains invalid application of percent-encoding");
                                else
                                    throw new Pkcs11UriException("URI contains invalid application of percent-encoding");
                            }

                            if (!IsHexDigit(pk11String[i + 1]) || !IsHexDigit(pk11String[i + 2]))
                            {
                                if (attributeName != null)
                                    throw new Pkcs11UriException("Value of " + attributeName + " attribute contains invalid application of percent-encoding");
                                else
                                    throw new Pkcs11UriException("URI contains invalid application of percent-encoding");
                            }

                            memoryStream.WriteByte(Convert.ToByte(pk11String.Substring(i + 1, 2), 16));
                            i = i + 3;
                            continue;
                        }
                    }

                    bool allowedChar = false;

                    for (int j = 0; j < allowedChars.Length; j++)
                    {
                        if (pk11String[i] == allowedChars[j])
                        {
                            allowedChar = true;
                            break;
                        }
                    }

                    if (allowedChar)
                    {
                        memoryStream.WriteByte(Convert.ToByte(pk11String[i]));
                        i++;
                        continue;
                    }

                    if (attributeName != null)
                        throw new Pkcs11UriException("Value of " + attributeName + " attribute contains invalid character");
                    else
                        throw new Pkcs11UriException("URI contains invalid character");
                }

                return memoryStream.ToArray();
            }
        }

        /// <summary>
        /// Checks whether character is hex digit
        /// </summary>
        /// <param name="c">Character that should be checked</param>
        /// <returns>True if character is hex digit false otherwise</returns>
        private bool IsHexDigit(char c)
        {
            return (((c >= 0x30) && (c <= 0x39)) || // 0-9
                    ((c >= 0x41) && (c <= 0x46)) || // A-F
                    ((c >= 0x61) && (c <= 0x66)));  // a-f
        }

        /// <summary>
        /// Checks whether string matches the value of string attribute
        /// </summary>
        /// <param name="uriString">Value of string attribute present (or not) in PKCS#11 URI</param>
        /// <param name="inputString">String that should be compared with the value of string attribute</param>
        /// <returns>True if string matches the value of string attribute</returns>
        private bool SimpleStringsMatch(string uriString, string inputString)
        {
            if (inputString == null)
            {
                if (uriString != null)
                    return false;
            }
            else
            {
                if (uriString != null)
                {
                    // No characters should be percent-encoded so there is no need to apply
                    // the case and the percent-encoding normalization specified in RFC3986
                    if (0 != string.Compare(uriString, inputString, false))
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Checks whether type matches the value of "type" path attribute
        /// </summary>
        /// <param name="uriType">Value of "type" path attribute present (or not) in PKCS#11 URI</param>
        /// <param name="inputType">Type that should be compared with the value of "type" path attribute</param>
        /// <returns>True if type matches the value of "type" path attribute</returns>
        private bool ObjectTypesMatch(CKO? uriType, CKO? inputType)
        {
            if (inputType == null)
            {
                if (uriType != null)
                    return false;
            }
            else
            {
                if (uriType != null)
                {
                    if (uriType.Value != inputType.Value)
                        return false;
                }
            }

            return true;
        }
        
        /// <summary>
        /// Checks whether byte array matches the value of "id" path attribute
        /// </summary>
        /// <param name="uriArray">Value of "id" path attribute present (or not) in PKCS#11 URI</param>
        /// <param name="inputArray">Byte array that should be compared with the value of "id" path attribute</param>
        /// <returns>True if byte array matches the value of "id" path attribute</returns>
        private bool ByteArraysMatch(byte[] uriArray, byte[] inputArray)
        {
            if (inputArray == null)
            {
                if (uriArray != null)
                    return false;
            }
            else
            {
                if (uriArray != null)
                {
                    if (uriArray.Length != inputArray.Length)
                        return false;

                    for (int i = 0; i < uriArray.Length; i++)
                    {
                        if (uriArray[i] != inputArray[i])
                            return false;
                    }
                }
            }

            return true;
        }

        #endregion
    }
}
