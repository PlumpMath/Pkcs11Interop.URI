/*
 *  Pkcs11Interop.URI - PKCS#11 URI extensions for Pkcs11Interop library
 *  Copyright (c) 2013-2015 JWC s.r.o. <http://www.jwc.sk>
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
using Net.Pkcs11Interop.Common;
using HLA = Net.Pkcs11Interop.HighLevelAPI;
using HLA4 = Net.Pkcs11Interop.HighLevelAPI4;
using HLA8 = Net.Pkcs11Interop.HighLevelAPI8;
using LLA4 = Net.Pkcs11Interop.LowLevelAPI4;
using LLA8 = Net.Pkcs11Interop.LowLevelAPI8;

namespace Net.Pkcs11Interop.URI
{
    /// <summary>
    /// Utility class connecting PKCS#11 URI and Pkcs11Interop types
    /// </summary>
    public static class Pkcs11UriUtils
    {
        #region PKCS#11 URI matching

        #region LibraryInfo

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="libraryManufacturer">PKCS#11 library manufacturer</param>
        /// <param name="libraryDescription">PKCS#11 library description</param>
        /// <param name="libraryVersion">PKCS#11 library version</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        private static bool Matches(Pkcs11Uri pkcs11Uri, string libraryManufacturer, string libraryDescription, string libraryVersion)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11Uri.UnknownPathAttributes != null)
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.LibraryManufacturer, libraryManufacturer))
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.LibraryDescription, libraryDescription))
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.LibraryVersion, libraryVersion))
                return false;

            return true;
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA.LibraryInfo libraryInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(pkcs11Uri, libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA8.LibraryInfo libraryInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(pkcs11Uri, libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA4.LibraryInfo libraryInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (libraryInfo == null)
                throw new ArgumentNullException("libraryInfo");

            return Matches(pkcs11Uri, libraryInfo.ManufacturerId, libraryInfo.LibraryDescription, libraryInfo.LibraryVersion);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, LLA8.CK_INFO libraryInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            string manufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
            string version = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);

            return Matches(pkcs11Uri, manufacturer, description, version);
        }

        /// <summary>
        /// Checks whether PKCS#11 library information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="libraryInfo">PKCS#11 library information</param>
        /// <returns>True if PKCS#11 library information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, LLA4.CK_INFO libraryInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            string manufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
            string version = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);

            return Matches(pkcs11Uri, manufacturer, description, version);
        }

        #endregion

        #region SlotInfo

        /// <summary>
        /// Checks whether slot information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="slotManufacturer">Slot manufacturer</param>
        /// <param name="slotDescription">Slot description</param>
        /// <param name="slotId">Slot identifier</param>
        /// <returns>True if slot information matches PKCS#11 URI</returns>
        private static bool Matches(Pkcs11Uri pkcs11Uri, string slotManufacturer, string slotDescription, ulong? slotId)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11Uri.UnknownPathAttributes != null)
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.SlotManufacturer, slotManufacturer))
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.SlotDescription, slotDescription))
                return false;

            if (!SlotIdsMatch(pkcs11Uri.SlotId, slotId))
                return false;

            return true;
        }

        /// <summary>
        /// Checks whether slot information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="slotInfo">Slot information</param>
        /// <returns>True if slot information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA.SlotInfo slotInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (slotInfo == null)
                throw new ArgumentNullException("slotInfo");

            return Matches(pkcs11Uri, slotInfo.ManufacturerId, slotInfo.SlotDescription, slotInfo.SlotId);
        }

        /// <summary>
        /// Checks whether slot information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="slotInfo">Slot information</param>
        /// <returns>True if slot information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA8.SlotInfo slotInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (slotInfo == null)
                throw new ArgumentNullException("slotInfo");

            return Matches(pkcs11Uri, slotInfo.ManufacturerId, slotInfo.SlotDescription, slotInfo.SlotId);
        }

        /// <summary>
        /// Checks whether slot information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="slotInfo">Slot information</param>
        /// <returns>True if slot information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA4.SlotInfo slotInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (slotInfo == null)
                throw new ArgumentNullException("slotInfo");

            return Matches(pkcs11Uri, slotInfo.ManufacturerId, slotInfo.SlotDescription, slotInfo.SlotId);
        }

        /// <summary>
        /// Checks whether slot information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="slotInfo">Slot information</param>
        /// <param name="slotId">Slot identifier</param>
        /// <returns>True if slot information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, LLA8.CK_SLOT_INFO slotInfo, ulong? slotId)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            string manufacturer = ConvertUtils.BytesToUtf8String(slotInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(slotInfo.SlotDescription, true);

            return Matches(pkcs11Uri, manufacturer, description, slotId);
        }

        /// <summary>
        /// Checks whether slot information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="slotInfo">Slot information</param>
        /// <param name="slotId">Slot identifier</param>
        /// <returns>True if slot information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, LLA4.CK_SLOT_INFO slotInfo, uint? slotId)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            string manufacturer = ConvertUtils.BytesToUtf8String(slotInfo.ManufacturerId, true);
            string description = ConvertUtils.BytesToUtf8String(slotInfo.SlotDescription, true);

            return Matches(pkcs11Uri, manufacturer, description, slotId);
        }

        #endregion

        #region TokenInfo

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="tokenLabel">Token label</param>
        /// <param name="tokenManufacturer">Token manufacturer</param>
        /// <param name="tokenSerial">Token serial number</param>
        /// <param name="tokenModel">Token model</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        private static bool Matches(Pkcs11Uri pkcs11Uri, string tokenLabel, string tokenManufacturer, string tokenSerial, string tokenModel)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11Uri.UnknownPathAttributes != null)
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.Token, tokenLabel))
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.Manufacturer, tokenManufacturer))
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.Serial, tokenSerial))
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.Model, tokenModel))
                return false;

            return true;
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA.TokenInfo tokenInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(pkcs11Uri, tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA8.TokenInfo tokenInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(pkcs11Uri, tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, HLA4.TokenInfo tokenInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            return Matches(pkcs11Uri, tokenInfo.Label, tokenInfo.ManufacturerId, tokenInfo.SerialNumber, tokenInfo.Model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, LLA8.CK_TOKEN_INFO tokenInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            string token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
            string manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
            string serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
            string model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);

            return Matches(pkcs11Uri, token, manufacturer, serial, model);
        }

        /// <summary>
        /// Checks whether token information matches PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="tokenInfo">Token information</param>
        /// <returns>True if token information matches PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, LLA4.CK_TOKEN_INFO tokenInfo)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            string token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
            string manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
            string serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
            string model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);

            return Matches(pkcs11Uri, token, manufacturer, serial, model);
        }

        #endregion

        #region ObjectAttributes

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="ckaClass">Value of CKA_CLASS object attribute</param>
        /// <param name="ckaLabel">Value of CKA_LABEL object attribute</param>
        /// <param name="ckaId">Value of CKA_ID object attribute</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        private static bool Matches(Pkcs11Uri pkcs11Uri, CKO? ckaClass, string ckaLabel, byte[] ckaId)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11Uri.UnknownPathAttributes != null)
                return false;

            if (!ObjectTypesMatch(pkcs11Uri.Type, ckaClass))
                return false;

            if (!SimpleStringsMatch(pkcs11Uri.Object, ckaLabel))
                return false;

            if (!ByteArraysMatch(pkcs11Uri.Id, ckaId))
                return false;

            return true;
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, List<HLA.ObjectAttribute> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

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

            if ((!ckaClassFound) && (pkcs11Uri.Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (pkcs11Uri.Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (pkcs11Uri.Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(pkcs11Uri, ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, List<HLA8.ObjectAttribute> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

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

            if ((!ckaClassFound) && (pkcs11Uri.Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (pkcs11Uri.Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (pkcs11Uri.Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(pkcs11Uri, ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, List<HLA4.ObjectAttribute> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

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

            foreach (HLA4.ObjectAttribute objectAttribute in objectAttributes)
            {
                if (objectAttribute == null)
                    continue;

                if (objectAttribute.Type == ckaClassType)
                {
                    ckaClassValue = (CKO)objectAttribute.GetValueAsUint();
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

            if ((!ckaClassFound) && (pkcs11Uri.Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (pkcs11Uri.Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (pkcs11Uri.Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(pkcs11Uri, ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, List<LLA8.CK_ATTRIBUTE> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

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

            if ((!ckaClassFound) && (pkcs11Uri.Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (pkcs11Uri.Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (pkcs11Uri.Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(pkcs11Uri, ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        /// <summary>
        /// Checks whether object attributes match PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">Object attributes</param>
        /// <returns>True if object attributes match PKCS#11 URI</returns>
        public static bool Matches(Pkcs11Uri pkcs11Uri, List<LLA4.CK_ATTRIBUTE> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

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

            if ((!ckaClassFound) && (pkcs11Uri.Type != null))
                throw new Pkcs11UriException("CKA_CLASS attribute is not present in the list of object attributes");

            if ((!ckaLabelFound) && (pkcs11Uri.Object != null))
                throw new Pkcs11UriException("CKA_LABEL attribute is not present in the list of object attributes");

            if ((!ckaIdFound) && (pkcs11Uri.Id != null))
                throw new Pkcs11UriException("CKA_ID attribute is not present in the list of object attributes");

            return Matches(pkcs11Uri, ckaClassValue, ckaLabelValue, ckaIdValue);
        }

        #endregion

        #region GetMatchingSlotList

        /// <summary>
        /// Obtains a list of all PKCS#11 URI matching slots
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <param name="tokenPresent">Flag indicating whether the list obtained includes only those slots with a token present (true), or all slots (false)</param>
        /// <returns>List of slots matching PKCS#11 URI</returns>
        public static List<HLA.Slot> GetMatchingSlotList(Pkcs11Uri pkcs11Uri, HLA.Pkcs11 pkcs11, bool tokenPresent)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<HLA.Slot> matchingSlots = new List<HLA.Slot>();

            HLA.LibraryInfo libraryInfo = pkcs11.GetInfo();
            if (!Matches(pkcs11Uri, libraryInfo))
                return matchingSlots;

            List<HLA.Slot> slots = pkcs11.GetSlotList(false);
            if ((slots == null) || (slots.Count == 0))
                return slots;

            foreach (HLA.Slot slot in slots)
            {
                HLA.SlotInfo slotInfo = slot.GetSlotInfo();
                if (Matches(pkcs11Uri, slotInfo))
                {
                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        HLA.TokenInfo tokenInfo = slot.GetTokenInfo();
                        if (Matches(pkcs11Uri, tokenInfo))
                            matchingSlots.Add(slot);
                    }
                    else
                    {
                        if (!tokenPresent && Matches(pkcs11Uri, null, null, null, null))
                            matchingSlots.Add(slot);
                    }
                }
            }

            return matchingSlots;
        }

        /// <summary>
        /// Obtains a list of all PKCS#11 URI matching slots
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <param name="tokenPresent">Flag indicating whether the list obtained includes only those slots with a token present (true), or all slots (false)</param>
        /// <returns>List of slots matching PKCS#11 URI</returns>
        public static List<HLA8.Slot> GetMatchingSlotList(Pkcs11Uri pkcs11Uri, HLA8.Pkcs11 pkcs11, bool tokenPresent)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<HLA8.Slot> matchingSlots = new List<HLA8.Slot>();

            HLA8.LibraryInfo libraryInfo = pkcs11.GetInfo();
            if (!Matches(pkcs11Uri, libraryInfo))
                return matchingSlots;

            List<HLA8.Slot> slots = pkcs11.GetSlotList(false);
            if ((slots == null) || (slots.Count == 0))
                return slots;

            foreach (HLA8.Slot slot in slots)
            {
                HLA8.SlotInfo slotInfo = slot.GetSlotInfo();
                if (Matches(pkcs11Uri, slotInfo))
                {
                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        HLA8.TokenInfo tokenInfo = slot.GetTokenInfo();
                        if (Matches(pkcs11Uri, tokenInfo))
                            matchingSlots.Add(slot);
                    }
                    else
                    {
                        if (!tokenPresent && Matches(pkcs11Uri, null, null, null, null))
                            matchingSlots.Add(slot);
                    }
                }
            }

            return matchingSlots;
        }

        /// <summary>
        /// Obtains a list of all PKCS#11 URI matching slots
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <param name="tokenPresent">Flag indicating whether the list obtained includes only those slots with a token present (true), or all slots (false)</param>
        /// <returns>List of slots matching PKCS#11 URI</returns>
        public static List<HLA4.Slot> GetMatchingSlotList(Pkcs11Uri pkcs11Uri, HLA4.Pkcs11 pkcs11, bool tokenPresent)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<HLA4.Slot> matchingSlots = new List<HLA4.Slot>();

            HLA4.LibraryInfo libraryInfo = pkcs11.GetInfo();
            if (!Matches(pkcs11Uri, libraryInfo))
                return matchingSlots;

            List<HLA4.Slot> slots = pkcs11.GetSlotList(false);
            if ((slots == null) || (slots.Count == 0))
                return slots;

            foreach (HLA4.Slot slot in slots)
            {
                HLA4.SlotInfo slotInfo = slot.GetSlotInfo();
                if (Matches(pkcs11Uri, slotInfo))
                {
                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        HLA4.TokenInfo tokenInfo = slot.GetTokenInfo();
                        if (Matches(pkcs11Uri, tokenInfo))
                            matchingSlots.Add(slot);
                    }
                    else
                    {
                        if (!tokenPresent && Matches(pkcs11Uri, null, null, null, null))
                            matchingSlots.Add(slot);
                    }
                }
            }

            return matchingSlots;
        }

        /// <summary>
        /// Obtains a list of all slots where token that matches PKCS#11 URI is present
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="pkcs11">Low level PKCS#11 wrapper</param>
        /// <param name="tokenPresent">Flag indicating whether the list obtained includes only those slots with a token present (true), or all slots (false)</param>
        /// <param name="slotList">List of slots matching PKCS#11 URI</param>
        /// <returns>CKR_OK if successful; any other value otherwise</returns>
        public static CKR GetMatchingSlotList(Pkcs11Uri pkcs11Uri, LLA8.Pkcs11 pkcs11, bool tokenPresent, out ulong[] slotList)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<ulong> matchingSlots = new List<ulong>();

            // Get library information
            LLA8.CK_INFO libraryInfo = new LLA8.CK_INFO();
            CKR rv = pkcs11.C_GetInfo(ref libraryInfo);
            if (rv != CKR.CKR_OK)
            {
                slotList = new ulong[0];
                return rv;
            }

            // Check whether library matches URI
            if (!Matches(pkcs11Uri, libraryInfo))
            {
                slotList = new ulong[0];
                return CKR.CKR_OK;
            }

            // Get number of slots in first call
            ulong slotCount = 0;
            rv = pkcs11.C_GetSlotList(false, null, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = new ulong[0];
                return rv;
            }

            if (slotCount < 1)
            {
                slotList = new ulong[0];
                return CKR.CKR_OK;
            }

            // Allocate array for slot IDs
            ulong[] slots = new ulong[slotCount];

            // Get slot IDs in second call
            rv = pkcs11.C_GetSlotList(tokenPresent, slots, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = new ulong[0];
                return rv;
            }

            // Shrink array if needed
            if (slots.Length != Convert.ToInt32(slotCount))
                Array.Resize(ref slots, Convert.ToInt32(slotCount));

            // Match slots with Pkcs11Uri
            foreach (ulong slot in slots)
            {
                LLA8.CK_SLOT_INFO slotInfo = new LLA8.CK_SLOT_INFO();
                rv = pkcs11.C_GetSlotInfo(slot, ref slotInfo);
                if (rv != CKR.CKR_OK)
                {
                    slotList = new ulong[0];
                    return rv;
                }

                // Check whether slot matches URI
                if (Matches(pkcs11Uri, slotInfo, slot))
                {
                    if ((slotInfo.Flags & CKF.CKF_TOKEN_PRESENT) == CKF.CKF_TOKEN_PRESENT)
                    {
                        LLA8.CK_TOKEN_INFO tokenInfo = new LLA8.CK_TOKEN_INFO();
                        rv = pkcs11.C_GetTokenInfo(slot, ref tokenInfo);
                        if (rv != CKR.CKR_OK)
                        {
                            slotList = new ulong[0];
                            return rv;
                        }

                        // Check whether token matches URI
                        if (Matches(pkcs11Uri, tokenInfo))
                            matchingSlots.Add(slot);
                    }
                    else
                    {
                        if (!tokenPresent && Matches(pkcs11Uri, null, null, null, null))
                            matchingSlots.Add(slot);
                    }
                }
            }

            slotList = matchingSlots.ToArray();
            return CKR.CKR_OK;
        }

        /// <summary>
        /// Obtains a list of all slots where token that matches PKCS#11 URI is present
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="pkcs11">Low level PKCS#11 wrapper</param>
        /// <param name="tokenPresent">Flag indicating whether the list obtained includes only those slots with a token present (true), or all slots (false)</param>
        /// <param name="slotList">List of slots matching PKCS#11 URI</param>
        /// <returns>CKR_OK if successful; any other value otherwise</returns>
        public static CKR GetMatchingSlotList(Pkcs11Uri pkcs11Uri, LLA4.Pkcs11 pkcs11, bool tokenPresent, out uint[] slotList)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            List<uint> matchingSlots = new List<uint>();

            // Get library information
            LLA4.CK_INFO libraryInfo = new LLA4.CK_INFO();
            CKR rv = pkcs11.C_GetInfo(ref libraryInfo);
            if (rv != CKR.CKR_OK)
            {
                slotList = new uint[0];
                return rv;
            }

            // Check whether library matches URI
            if (!Matches(pkcs11Uri, libraryInfo))
            {
                slotList = new uint[0];
                return CKR.CKR_OK;
            }

            // Get number of slots in first call
            uint slotCount = 0;
            rv = pkcs11.C_GetSlotList(false, null, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = new uint[0];
                return rv;
            }

            if (slotCount < 1)
            {
                slotList = new uint[0];
                return CKR.CKR_OK;
            }

            // Allocate array for slot IDs
            uint[] slots = new uint[slotCount];

            // Get slot IDs in second call
            rv = pkcs11.C_GetSlotList(tokenPresent, slots, ref slotCount);
            if (rv != CKR.CKR_OK)
            {
                slotList = new uint[0];
                return rv;
            }

            // Shrink array if needed
            if (slots.Length != slotCount)
                Array.Resize(ref slots, Convert.ToInt32(slotCount));

            // Match slots with Pkcs11Uri
            foreach (uint slot in slots)
            {
                LLA4.CK_SLOT_INFO slotInfo = new LLA4.CK_SLOT_INFO();
                rv = pkcs11.C_GetSlotInfo(slot, ref slotInfo);
                if (rv != CKR.CKR_OK)
                {
                    slotList = new uint[0];
                    return rv;
                }

                // Check whether slot matches URI
                if (Matches(pkcs11Uri, slotInfo, slot))
                {
                    if ((slotInfo.Flags & CKF.CKF_TOKEN_PRESENT) == CKF.CKF_TOKEN_PRESENT)
                    {
                        LLA4.CK_TOKEN_INFO tokenInfo = new LLA4.CK_TOKEN_INFO();
                        rv = pkcs11.C_GetTokenInfo(slot, ref tokenInfo);
                        if (rv != CKR.CKR_OK)
                        {
                            slotList = new uint[0];
                            return rv;
                        }

                        // Check whether token matches URI
                        if (Matches(pkcs11Uri, tokenInfo))
                            matchingSlots.Add(slot);
                    }
                    else
                    {
                        if (!tokenPresent && Matches(pkcs11Uri, null, null, null, null))
                            matchingSlots.Add(slot);
                    }
                }
            }

            slotList = matchingSlots.ToArray();
            return CKR.CKR_OK;
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Checks whether string matches the value of string attribute
        /// </summary>
        /// <param name="uriString">Value of string attribute present (or not) in PKCS#11 URI</param>
        /// <param name="inputString">String that should be compared with the value of string attribute</param>
        /// <returns>True if string matches the value of string attribute</returns>
        private static bool SimpleStringsMatch(string uriString, string inputString)
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
        private static bool ObjectTypesMatch(CKO? uriType, CKO? inputType)
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
        private static bool ByteArraysMatch(byte[] uriArray, byte[] inputArray)
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

        /// <summary>
        /// Checks whether id matches the value of "slot-id" path attribute
        /// </summary>
        /// <param name="uriId">Value of "slot-id" path attribute present (or not) in PKCS#11 URI</param>
        /// <param name="inputId">Id that should be compared with the value of "slot-id" path attribute</param>
        /// <returns>True if id matches the value of "slot-id" path attribute</returns>
        private static bool SlotIdsMatch(ulong? uriId, ulong? inputId)
        {
            if (inputId == null)
            {
                if (uriId != null)
                    return false;
            }
            else
            {
                if (uriId != null)
                {
                    if (uriId.Value != inputId.Value)
                        return false;
                }
            }

            return true;
        }

        #endregion

        #endregion

        #region PKCS#11 URI object attributes extraction

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public static void GetObjectAttributes(Pkcs11Uri pkcs11Uri, out List<HLA.ObjectAttribute> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            List<HLA.ObjectAttribute> attributes = null;

            if (pkcs11Uri.DefinesObject)
            {
                attributes = new List<HLA.ObjectAttribute>();
                if (pkcs11Uri.Type != null)
                    attributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, pkcs11Uri.Type.Value));
                if (pkcs11Uri.Object != null)
                    attributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, pkcs11Uri.Object));
                if (pkcs11Uri.Id != null)
                    attributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, pkcs11Uri.Id));
            }

            objectAttributes = attributes;
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public static void GetObjectAttributes(Pkcs11Uri pkcs11Uri, out List<HLA8.ObjectAttribute> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            List<HLA8.ObjectAttribute> attributes = null;

            if (pkcs11Uri.DefinesObject)
            {
                attributes = new List<HLA8.ObjectAttribute>();
                if (pkcs11Uri.Type != null)
                    attributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, pkcs11Uri.Type.Value));
                if (pkcs11Uri.Object != null)
                    attributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, pkcs11Uri.Object));
                if (pkcs11Uri.Id != null)
                    attributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, pkcs11Uri.Id));
            }

            objectAttributes = attributes;
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public static void GetObjectAttributes(Pkcs11Uri pkcs11Uri, out List<HLA4.ObjectAttribute> objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            List<HLA4.ObjectAttribute> attributes = null;

            if (pkcs11Uri.DefinesObject)
            {
                attributes = new List<HLA4.ObjectAttribute>();
                if (pkcs11Uri.Type != null)
                    attributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, pkcs11Uri.Type.Value));
                if (pkcs11Uri.Object != null)
                    attributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, pkcs11Uri.Object));
                if (pkcs11Uri.Id != null)
                    attributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, pkcs11Uri.Id));
            }

            objectAttributes = attributes;
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public static void GetObjectAttributes(Pkcs11Uri pkcs11Uri, out LLA8.CK_ATTRIBUTE[] objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            List<LLA8.CK_ATTRIBUTE> attributes = null;

            if (pkcs11Uri.DefinesObject)
            {
                attributes = new List<LLA8.CK_ATTRIBUTE>();
                if (pkcs11Uri.Type != null)
                    attributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, pkcs11Uri.Type.Value));
                if (pkcs11Uri.Object != null)
                    attributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, pkcs11Uri.Object));
                if (pkcs11Uri.Id != null)
                    attributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, pkcs11Uri.Id));
            }

            objectAttributes = attributes.ToArray();
        }

        /// <summary>
        /// Returns list of object attributes defined by PKCS#11 URI
        /// </summary>
        /// <param name="pkcs11Uri">PKCS#11 URI</param>
        /// <param name="objectAttributes">List of object attributes defined by PKCS#11 URI</param>
        public static void GetObjectAttributes(Pkcs11Uri pkcs11Uri, out LLA4.CK_ATTRIBUTE[] objectAttributes)
        {
            if (pkcs11Uri == null)
                throw new ArgumentNullException("pkcs11Uri");

            List<LLA4.CK_ATTRIBUTE> attributes = null;

            if (pkcs11Uri.DefinesObject)
            {
                attributes = new List<LLA4.CK_ATTRIBUTE>();
                if (pkcs11Uri.Type != null)
                    attributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, pkcs11Uri.Type.Value));
                if (pkcs11Uri.Object != null)
                    attributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, pkcs11Uri.Object));
                if (pkcs11Uri.Id != null)
                    attributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, pkcs11Uri.Id));
            }

            objectAttributes = attributes.ToArray();
        }

        #endregion
    }
}
