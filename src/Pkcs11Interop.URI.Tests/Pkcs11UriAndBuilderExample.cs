﻿/*
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
using Net.Pkcs11Interop.HighLevelAPI;
using NUnit.Framework;

namespace Net.Pkcs11Interop.URI.Tests
{
    /// <summary>
    /// Official code samples for Pkcs11Interop.URI library 
    /// </summary>
    [TestFixture()]
    public class Pkcs11UriAndBuilderExample
    {
        /// <summary>
        /// Demonstration of PKCS#11 URI usage in the signature creation application
        /// </summary>
        [Test()]
        public void Pkcs11UriInSignatureCreationApplication()
        {
            byte[] dataToSign = ConvertUtils.Utf8StringToBytes("Hello world");
            
            // PKCS#11 URI can be acquired i.e. from configuration file as a simple string...
            string uri = @"<pkcs11:serial=7BFF2737350B262C;
                            type=private;
                            object=John%20Doe
                            ?module-path=siecap11.dll&
                            pin-value=11111111>";

            // ...or it can be easily constructed with Pkcs11UriBuilder
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Serial = "7BFF2737350B262C";
            pkcs11UriBuilder.Type = CKO.CKO_PRIVATE_KEY;
            pkcs11UriBuilder.Object = "John Doe";
            pkcs11UriBuilder.ModulePath = "siecap11.dll";
            pkcs11UriBuilder.PinValue = "11111111";
            uri = pkcs11UriBuilder.ToString();

            // Warning: Please note that PIN stored in PKCS#11 URI can pose a security risk and therefore other options
            //          should be carefully considered. For example an application may ask for a PIN with a GUI dialog etc.

            // Use PKCS#11 URI to identify private key in signature creation method
            byte[] signature = SignData(dataToSign, uri);

            // Do something interesting with the signature
        }

        /// <summary>
        /// Creates the PKCS#1 v1.5 RSA signature with SHA-1 mechanism
        /// </summary>
        /// <param name="data">Data that should be signed</param>
        /// <param name="uri">PKCS#11 URI identifying PKCS#11 library, token and private key</param>
        /// <returns>Signature</returns>
        private byte[] SignData(byte[] data, string uri)
        {
            // Verify input parameters
            if (data == null)
                throw new ArgumentNullException("data");

            if (string.IsNullOrEmpty(uri))
                throw new ArgumentNullException("uri");

            // Parse PKCS#11 URI
            Pkcs11Uri pkcs11Uri = new Pkcs11Uri(uri);

            // Verify that URI contains all information required to perform this operation
            if (pkcs11Uri.ModulePath == null)
                throw new Exception("PKCS#11 URI does not specify PKCS#11 library");

            if (pkcs11Uri.PinValue == null)
                throw new Exception("PKCS#11 URI does not specify PIN");

            if (!pkcs11Uri.DefinesObject || pkcs11Uri.Type != CKO.CKO_PRIVATE_KEY)
                throw new Exception("PKCS#11 URI does not specify private key");

            // Load and initialize PKCS#11 library specified by URI
            using (Pkcs11 pkcs11 = new Pkcs11(pkcs11Uri.ModulePath, true))
            {
                //  Obtain a list of all slots with tokens that match URI
                List<Slot> slots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11Uri, pkcs11, true);
                if ((slots == null) || (slots.Count == 0))
                    throw new Exception("None of the slots matches PKCS#11 URI");

                // Open read only session with first token that matches URI
                using (Session session = slots[0].OpenSession(true))
                {
                    // Login as normal user with PIN acquired from URI
                    session.Login(CKU.CKU_USER, pkcs11Uri.PinValue);

                    // Get list of object attributes for the private key specified by URI
                    List<ObjectAttribute> searchTemplate = null;
                    Pkcs11UriUtils.GetObjectAttributes(pkcs11Uri, out searchTemplate);

                    // Find private key specified by URI
                    List<ObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
                    if ((foundObjects == null) || (foundObjects.Count == 0))
                        throw new Exception("None of the private keys match PKCS#11 URI");

                    // Create signature with the private key specified by URI
                    return session.Sign(new Mechanism(CKM.CKM_SHA1_RSA_PKCS), foundObjects[0], data);
                }
            }
        }
    }
}
