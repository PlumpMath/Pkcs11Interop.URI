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
    public class Pkcs11Uri
    {
        #region Constructors

        public Pkcs11Uri(string uri)
            : this(uri, true)
        {

        }

        public Pkcs11Uri(string uri, bool checkLengths)
        {
            if (string.IsNullOrEmpty(uri))
                throw new ArgumentNullException("uri");

            _checkLengths = checkLengths;

            Parse(Extract(uri));
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

        #region Flags
        
        public bool DefinesLibrary
        {
            get
            {
                return (LibraryManufacturer != null ||
                        LibraryDescription != null ||
                        LibraryVersion != null ||
                        XLibraryPath != null);
            }
        }

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

        private string _token = null;

        public string Token
        {
            get
            {
                return _token;
            }
        }

        private string _manufacturer = null;

        public string Manufacturer
        {
            get
            {
                return _manufacturer;
            }
        }

        private string _serial = null;

        public string Serial
        {
            get
            {
                return _serial;
            }
        }

        private string _model = null;

        public string Model
        {
            get
            {
                return _model;
            }
        }

        private string _libraryManufacturer = null;

        public string LibraryManufacturer
        {
            get
            {
                return _libraryManufacturer;
            }
        }

        private string _libraryDescription = null;

        public string LibraryDescription
        {
            get
            {
                return _libraryDescription;
            }
        }

        private string _libraryVersion = null;

        public string LibraryVersion
        {
            get
            {
                return _libraryVersion;
            }
        }

        private string _object = null;

        public string Object
        {
            get
            {
                return _object;
            }
        }

        private CKO? _type = null;

        public CKO? Type
        {
            get
            {
                return _type;
            }
        }

        private byte[] _id = null;

        public byte[] Id
        {
            get
            {
                return _id;
            }
        }

        private Dictionary<string, string> _unknownPathAttributes = null;

        public Dictionary<string, string> UnknownPathAttributes
        {
            get
            {
                return _unknownPathAttributes;
            }
        }

        #region GetObjectAttributes

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

        private string _pinSource = null;

        public string PinSource
        {
            get
            {
                return _pinSource;
            }
        }

        private string _xPinValue = null;

        public string XPinValue
        {
            get
            {
                return _xPinValue;
            }
        }

        private string _xLibraryPath = null;

        public string XLibraryPath
        {
            get
            {
                return _xLibraryPath;
            }
        }

        private Dictionary<string, List<string>> _unknownQueryAttributes = null;

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

        public bool Matches(HLA.LibraryInfo libraryInfo)
        {
            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        public bool Matches(HLA8.LibraryInfo libraryInfo)
        {
            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        public bool Matches(HLA4.LibraryInfo libraryInfo)
        {
            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        public bool Matches(LLA8.CK_INFO libraryInfo)
        {
            string manufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
            string version = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);

            return Matches(manufacturer, description, version);
        }

        public bool Matches(LLA4.CK_INFO libraryInfo)
        {
            string manufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
            string version = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);

            return Matches(manufacturer, description, version);
        }

        #endregion

        #region TokenInfo

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

        public bool Matches(HLA.TokenInfo tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        public bool Matches(HLA8.TokenInfo tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        public bool Matches(HLA4.TokenInfo tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        public bool Matches(LLA8.CK_TOKEN_INFO tokenInfo)
        {
            string token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
            string manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
            string serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
            string model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);

            return Matches(token, manufacturer, serial, model);
        }

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

        private string Extract(string uri)
        {
            if (string.IsNullOrEmpty(uri))
                throw new ArgumentNullException("uri");

            StringBuilder stringBuilder = new StringBuilder(uri.Length);
            for (int i = 0; i < uri.Length; i++)
                if (!char.IsWhiteSpace(uri[i]))
                    stringBuilder.Append(uri[i]);

            string extractedUri = stringBuilder.ToString();

            int firstCharPosition = 0;
            int lastCharPosition = 0;

            firstCharPosition = extractedUri.IndexOf(Pkcs11UriSpec.Pk11UriSchemeName + Pkcs11UriSpec.Pk11UriAndPathSeparator, StringComparison.InvariantCulture);
            if (firstCharPosition > 0)
            {
                if (extractedUri[firstCharPosition - 1] == '"')
                {
                    extractedUri = extractedUri.Remove(0, firstCharPosition);
                    lastCharPosition = extractedUri.IndexOf('"');
                }
                else if (extractedUri[firstCharPosition - 1] == '<')
                {
                    extractedUri = extractedUri.Remove(0, firstCharPosition);
                    lastCharPosition = extractedUri.IndexOf('>');
                }
                else
                    throw new Pkcs11UriException("URI is not delimited within double quotes or angle brackets");

                if (lastCharPosition < 0)
                    throw new Pkcs11UriException("URI is not correctly delimited within double quotes or angle brackets");

                extractedUri = extractedUri.Substring(0, lastCharPosition);
            }

            return extractedUri;
        }

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

                case Pkcs11UriSpec.Pk11XPinValue:

                    if (_xPinValue != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the query component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                        _xPinValue = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        _xPinValue = string.Empty;
                    }

                    break;

                case Pkcs11UriSpec.Pk11XLibraryPath:

                    if (_xLibraryPath != null)
                        throw new Pkcs11UriException("Duplicate attribute " + attributeName + " found in the query component");

                    if (attributeValue != string.Empty)
                    {
                        byte[] bytes = DecodePk11String(attributeName, attributeValue, Pkcs11UriSpec.Pk11QueryAttrValueChars, true);
                        _xLibraryPath = ConvertUtils.BytesToUtf8String(bytes);
                    }
                    else
                    {
                        throw new Pkcs11UriException("Value of " + attributeName + " attribute cannot be empty");
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

        private byte[] DecodePk11String(string attributeName, string attributeValue, char[] allowedChars, bool decodePctEncodedChars)
        {
            if (string.IsNullOrEmpty(attributeValue))
                return null;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                int i = 0;

                while (i < attributeValue.Length)
                {
                    if (decodePctEncodedChars)
                    {
                        if (attributeValue[i] == '%')
                        {
                            if ((i + 2) > attributeValue.Length)
                            {
                                if (attributeName != null)
                                    throw new Pkcs11UriException("Value of " + attributeName + " attribute contains invalid application of percent-encoding");
                                else
                                    throw new Pkcs11UriException("URI contains invalid application of percent-encoding");
                            }

                            if (!IsHexDigit(attributeValue[i + 1]) || !IsHexDigit(attributeValue[i + 2]))
                            {
                                if (attributeName != null)
                                    throw new Pkcs11UriException("Value of " + attributeName + " attribute contains invalid application of percent-encoding");
                                else
                                    throw new Pkcs11UriException("URI contains invalid application of percent-encoding");
                            }

                            memoryStream.WriteByte(Convert.ToByte(attributeValue.Substring(i + 1, 2), 16));
                            i = i + 3;
                            continue;
                        }
                    }

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
                        memoryStream.WriteByte(Convert.ToByte(attributeValue[i]));
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

        private bool IsHexDigit(char c)
        {
            return (((c >= 0x30) && (c <= 0x39)) || // 0-9
                    ((c >= 0x41) && (c <= 0x46)) || // A-F
                    ((c >= 0x61) && (c <= 0x66)));  // a-f
        }

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
