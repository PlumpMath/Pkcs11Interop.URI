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
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using NUnit.Framework;

namespace Net.Pkcs11Interop.URI.Tests
{
    [TestFixture()]
    public class Pkcs11UriExample
    {
        [Test()]
        public void Pkcs11UriÏnSignatureCreationApplication()
        {
            byte[] dataToSign = ConvertUtils.Utf8StringToBytes("Hello world");
            
            string uri = @"<pkcs11:serial=7BFF2737350B262C;
                            type=private;
                            object=John%20Doe
                            ?x-pin-value=11111111&
                            x-library-path=siecap11.dll>";

            Pkcs11Uri pkcs11Uri = new Pkcs11Uri(uri);

            if (pkcs11Uri.XLibraryPath == null)
                throw new Exception("PKCS#11 URI does not specify PKCS#11 library");

            if (pkcs11Uri.Type != CKO.CKO_PRIVATE_KEY)
                throw new Exception("PKCS#11 URI does not specify private key");

            using (Pkcs11 pkcs11 = new Pkcs11(pkcs11Uri.XLibraryPath, true))
            {
                List<Slot> slots = pkcs11Uri.GetMatchingSlotList(pkcs11);
                if ((slots == null) || (slots.Count == 0))
                    throw new Exception("None of the slots matches PKCS#11 URI");

                using (Session session = slots[0].OpenSession(true))
                {
                    session.Login(CKU.CKU_USER, pkcs11Uri.XPinValue);

                    List<ObjectAttribute> searchTemplate = null;
                    pkcs11Uri.GetObjectAttributes(out searchTemplate);

                    List<ObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
                    if ((foundObjects == null) || (foundObjects.Count == 0))
                        throw new Exception("None of the private keys match PKCS#11 URI");

                    byte[] signature = session.Sign(new Mechanism(CKM.CKM_SHA1_RSA_PKCS), foundObjects[0], dataToSign);

                    // Do something interesting with signature
                }
            }
        }
    }
}
