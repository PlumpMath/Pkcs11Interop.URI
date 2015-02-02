/*
 *  Pkcs11Interop.URI.Demo - Demonstration application
 *                           for Pkcs11Interop.URI library
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
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.URI
{
    /// <summary>
    /// Demonstration application for Pkcs11Interop.URI library
    /// </summary>
    static class DemoApp
    {
        /// <summary>
        /// Exit code indicating success
        /// </summary>
        const int _exitSuccess = 0;

        /// <summary>
        /// Exit code indicating error
        /// </summary>
        const int _exitError = 1;

        /// <summary>
        /// Command line argument that specifies PKCS#11 URI
        /// </summary>
        const string _argUri = "--uri";

        /// <summary>
        /// Command line argument that enables mode which lists all available slots
        /// </summary>
        const string _argListSlots = "--list-slots";

        /// <summary>
        /// Command line argument that enables mode which lists all available tokens
        /// </summary>
        const string _argListTokens = "--list-tokens";

        /// <summary>
        /// Command line argument that enables mode which lists available objects on specified token
        /// </summary>
        const string _argListObjects = "--list-objects";

        /// <summary>
        /// Main method specifying where program execution is to begin
        /// </summary>
        /// <param name="args">Command line arguments passed to the program</param>
        static void Main(string[] args)
        {
            try
            {
                // Parse command line arguments
                string uri = null;
                int listSlots = 0;
                int listTokens = 0;
                int listObjects = 0;

                if (args.Length == 0)
                    ExitWithHelp(null);

                int i = 0;
                while (i < args.Length)
                {
                    switch (args[i])
                    {
                        case _argUri:
                            uri = args[++i];
                            break;
                        case _argListSlots:
                            listSlots = 1;
                            break;
                        case _argListTokens:
                            listTokens = 1;
                            break;
                        case _argListObjects:
                            listObjects = 1;
                            break;
                        default:
                            ExitWithHelp("Invalid argument: " + args[i]);
                            break;
                    }

                    i++;
                }

                // Validate operation modes
                if (listSlots + listTokens + listObjects != 1)
                    ExitWithHelp(string.Format("Argument \"{0}\", \"{1}\" or \"{2}\" has to be specified", _argListSlots, _argListTokens, _argListObjects));

                #region List slots

                // Handle "--list-slots" operation mode
                if (listSlots == 1)
                {
                    // Validate command line arguments
                    if (string.IsNullOrEmpty(uri))
                        ExitWithHelp("Required argument: " + _argUri);

                    // Parse PKCS#11 URI
                    Pkcs11Uri pkcs11Uri = new Pkcs11Uri(uri);

                    // Verify that URI contains "module-path" attribute
                    if (string.IsNullOrEmpty(pkcs11Uri.ModulePath))
                        throw new Exception("PKCS#11 URI does not specify PKCS#11 library");

                    // Load and initialize PKCS#11 library specified by URI
                    using (Pkcs11 pkcs11 = new Pkcs11(pkcs11Uri.ModulePath, true))
                    {
                        Console.WriteLine("Listing available slots");

                        int j = 0;

                        //  Obtain a list of all slots
                        List<Slot> slots = pkcs11.GetSlotList(false);
                        foreach (Slot slot in slots)
                        {
                            j++;

                            // Obtain information about the particular slot
                            SlotInfo slotInfo = slot.GetSlotInfo();

                            // Build PKCS#11 URI for the particular slot
                            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                            pkcs11UriBuilder.ModulePath = pkcs11Uri.ModulePath;
                            pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                            pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                            pkcs11UriBuilder.SlotId = slotInfo.SlotId;

                            // Display slot information
                            Console.WriteLine();
                            Console.WriteLine("Slot no." + j);
                            Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
                            Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
                            Console.WriteLine("  ID:                 " + slotInfo.SlotId);
                            Console.WriteLine("  PKCS#11 URI:        " + pkcs11UriBuilder.ToString());
                        }

                        Console.WriteLine();
                        Console.WriteLine(string.Format("Total number of listed slots: {0}", j));
                    }
                }

                #endregion

                #region List tokens

                // Handle "--list-tokens" operation mode
                if (listTokens == 1)
                {
                    // Validate command line arguments
                    if (string.IsNullOrEmpty(uri))
                        ExitWithHelp("Required argument: " + _argUri);

                    // Parse PKCS#11 URI
                    Pkcs11Uri pkcs11Uri = new Pkcs11Uri(uri);

                    // Verify that URI contains "module-path" attribute
                    if (string.IsNullOrEmpty(pkcs11Uri.ModulePath))
                        throw new Exception("PKCS#11 URI does not specify PKCS#11 library");

                    // Load and initialize PKCS#11 library specified by URI
                    using (Pkcs11 pkcs11 = new Pkcs11(pkcs11Uri.ModulePath, true))
                    {
                        Console.WriteLine("Listing available tokens");

                        int j = 0;

                        //  Obtain a list of all slots with tokens
                        List<Slot> slots = pkcs11.GetSlotList(true);
                        foreach (Slot slot in slots)
                        {
                            j++;

                            // Obtain information about the particular token
                            TokenInfo tokenInfo = slot.GetTokenInfo();

                            // Build PKCS#11 URI for the particular token
                            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                            pkcs11UriBuilder.ModulePath = pkcs11Uri.ModulePath;
                            pkcs11UriBuilder.Token = tokenInfo.Label;
                            pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                            pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                            pkcs11UriBuilder.Model = tokenInfo.Model;

                            // Display token information
                            Console.WriteLine();
                            Console.WriteLine("Token no." + j);
                            Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                            Console.WriteLine("  Model:              " + tokenInfo.Model);
                            Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                            Console.WriteLine("  Label:              " + tokenInfo.Label);
                            Console.WriteLine("  PKCS#11 URI:        " + pkcs11UriBuilder.ToString());
                        }

                        Console.WriteLine();
                        Console.WriteLine(string.Format("Total number of listed tokens: {0}", j));
                    }
                }

                #endregion

                #region List objects

                // Handle "--list-objects" operation mode
                if (listObjects == 1)
                {
                    // Validate command line arguments
                    if (string.IsNullOrEmpty(uri))
                        ExitWithHelp("Required argument: " + _argUri);

                    // Parse PKCS#11 URI
                    Pkcs11Uri pkcs11Uri = new Pkcs11Uri(uri);

                    // Verify that URI contains "module-path" attribute
                    if (string.IsNullOrEmpty(pkcs11Uri.ModulePath))
                        throw new Exception("PKCS#11 URI does not specify PKCS#11 library");

                    // Load and initialize PKCS#11 library specified by URI
                    using (Pkcs11 pkcs11 = new Pkcs11(pkcs11Uri.ModulePath, true))
                    {
                        // Obtain a list of all slots with tokens matching provided URI
                        List<Slot> slots = pkcs11Uri.GetMatchingSlotList(pkcs11, true);
                        if (slots.Count == 0)
                            throw new Exception("No token matches provided PKCS#11 URI");
                        if (slots.Count > 1)
                            throw new Exception("More than one token matches provided PKCS#11 URI");

                        // Obtain information about the token
                        TokenInfo tokenInfo = slots[0].GetTokenInfo();

                        Console.WriteLine(string.Format("Listing objects available on token with serial \"{0}\" and label \"{1}\"", tokenInfo.SerialNumber, tokenInfo.Label));

                        Pkcs11UriBuilder pkcs11UriBuilder = null;
                        List<ObjectAttribute> searchTemplate = null;
                        List<ObjectHandle> foundObjects = null;
                        List<CKA> attributes = null;
                        List<ObjectAttribute> objectAttributes = null;
                        int j = 0;

                        // Open RO session with token
                        using (Session session = slots[0].OpenSession(true))
                        {
                            // Login if PIN has been provided
                            if (pkcs11Uri.PinValue != null)
                                session.Login(CKU.CKU_USER, pkcs11Uri.PinValue);

                            #region List data objects

                            searchTemplate = new List<ObjectAttribute>();
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA));

                            attributes = new List<CKA>();
                            attributes.Add(CKA.CKA_LABEL);

                            foundObjects = session.FindAllObjects(searchTemplate);
                            foreach (ObjectHandle foundObject in foundObjects)
                            {
                                j++;

                                objectAttributes = session.GetAttributeValue(foundObject, attributes);

                                pkcs11UriBuilder = new Pkcs11UriBuilder(pkcs11Uri);
                                pkcs11UriBuilder.Type = CKO.CKO_DATA;
                                pkcs11UriBuilder.Object = objectAttributes[0].GetValueAsString();
                                pkcs11UriBuilder.Id = null;

                                Console.WriteLine("");
                                Console.WriteLine("Object no." + j);
                                Console.WriteLine("  CKA_CLASS:             CKO_DATA");
                                Console.WriteLine("  CKA_LABEL:             " + pkcs11UriBuilder.Object);
                                Console.WriteLine("  PKCS#11 URI:           " + pkcs11UriBuilder.ToString());
                            }

                            #endregion

                            #region List private keys

                            searchTemplate = new List<ObjectAttribute>();
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));

                            attributes = new List<CKA>();
                            attributes.Add(CKA.CKA_ID);
                            attributes.Add(CKA.CKA_LABEL);
                            attributes.Add(CKA.CKA_KEY_TYPE);

                            foundObjects = session.FindAllObjects(searchTemplate);
                            foreach (ObjectHandle foundObject in foundObjects)
                            {
                                j++;

                                objectAttributes = session.GetAttributeValue(foundObject, attributes);

                                pkcs11UriBuilder = new Pkcs11UriBuilder(pkcs11Uri);
                                pkcs11UriBuilder.Type = CKO.CKO_PRIVATE_KEY;
                                pkcs11UriBuilder.Id = objectAttributes[0].GetValueAsByteArray();
                                pkcs11UriBuilder.Object = objectAttributes[1].GetValueAsString();
                                
                                Console.WriteLine("");
                                Console.WriteLine("Object no." + j);
                                Console.WriteLine("  CKA_CLASS:             CKO_PRIVATE_KEY");
                                Console.WriteLine("  CKA_ID:                " + ConvertUtils.BytesToHexString(pkcs11UriBuilder.Id));
                                Console.WriteLine("  CKA_LABEL:             " + pkcs11UriBuilder.Object);
                                Console.WriteLine("  CKA_KEY_TYPE:          " + ((CKK)objectAttributes[2].GetValueAsUlong()).ToString());
                                Console.WriteLine("  PKCS#11 URI:           " + pkcs11UriBuilder.ToString());
                            }

                            #endregion

                            #region List public keys

                            searchTemplate = new List<ObjectAttribute>();
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));

                            attributes = new List<CKA>();
                            attributes.Add(CKA.CKA_ID);
                            attributes.Add(CKA.CKA_LABEL);
                            attributes.Add(CKA.CKA_KEY_TYPE);

                            foundObjects = session.FindAllObjects(searchTemplate);
                            foreach (ObjectHandle foundObject in foundObjects)
                            {
                                j++;

                                objectAttributes = session.GetAttributeValue(foundObject, attributes);

                                pkcs11UriBuilder = new Pkcs11UriBuilder(pkcs11Uri);
                                pkcs11UriBuilder.Type = CKO.CKO_PUBLIC_KEY;
                                pkcs11UriBuilder.Id = objectAttributes[0].GetValueAsByteArray();
                                pkcs11UriBuilder.Object = objectAttributes[1].GetValueAsString();

                                Console.WriteLine("");
                                Console.WriteLine("Object no." + j);
                                Console.WriteLine("  CKA_CLASS:             CKO_PUBLIC_KEY");
                                Console.WriteLine("  CKA_ID:                " + ConvertUtils.BytesToHexString(pkcs11UriBuilder.Id));
                                Console.WriteLine("  CKA_LABEL:             " + pkcs11UriBuilder.Object);
                                Console.WriteLine("  CKA_KEY_TYPE:          " + ((CKK)objectAttributes[2].GetValueAsUlong()).ToString());
                                Console.WriteLine("  PKCS#11 URI:           " + pkcs11UriBuilder.ToString());
                            }

                            #endregion

                            #region List certificates

                            searchTemplate = new List<ObjectAttribute>();
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));

                            attributes = new List<CKA>();
                            attributes.Add(CKA.CKA_ID);
                            attributes.Add(CKA.CKA_LABEL);
                            attributes.Add(CKA.CKA_CERTIFICATE_TYPE);
                            attributes.Add(CKA.CKA_VALUE);

                            foundObjects = session.FindAllObjects(searchTemplate);
                            foreach (ObjectHandle foundObject in foundObjects)
                            {
                                j++;

                                objectAttributes = session.GetAttributeValue(foundObject, attributes);

                                pkcs11UriBuilder = new Pkcs11UriBuilder(pkcs11Uri);
                                pkcs11UriBuilder.Type = CKO.CKO_CERTIFICATE;
                                pkcs11UriBuilder.Id = objectAttributes[0].GetValueAsByteArray();
                                pkcs11UriBuilder.Object = objectAttributes[1].GetValueAsString();

                                Console.WriteLine("");
                                Console.WriteLine("Object no." + j);
                                Console.WriteLine("  CKA_CLASS:             CKO_CERTIFICATE");
                                Console.WriteLine("  CKA_ID:                " + ConvertUtils.BytesToHexString(pkcs11UriBuilder.Id));
                                Console.WriteLine("  CKA_LABEL:             " + pkcs11UriBuilder.Object);
                                Console.WriteLine("  CKA_CERTIFICATE_TYPE:  " + ((CKC)objectAttributes[2].GetValueAsUlong()).ToString());

                                if (CKC.CKC_X_509 == (CKC)objectAttributes[2].GetValueAsUlong())
                                {
                                    X509Certificate2 x509Cert = new X509Certificate2(objectAttributes[3].GetValueAsByteArray());

                                    Console.WriteLine("  Serial number:         " + x509Cert.SerialNumber);
                                    Console.WriteLine("  Subject DN:            " + x509Cert.Subject);
                                    Console.WriteLine("  Issuer DN:             " + x509Cert.Issuer);
                                    Console.WriteLine("  Not before:            " + x509Cert.NotBefore);
                                    Console.WriteLine("  Not after:             " + x509Cert.NotAfter);
                                }

                                Console.WriteLine("  PKCS#11 URI:           " + pkcs11UriBuilder.ToString());
                            }

                            #endregion

                            #region List secret keys

                            searchTemplate = new List<ObjectAttribute>();
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));

                            attributes = new List<CKA>();
                            attributes.Add(CKA.CKA_ID);
                            attributes.Add(CKA.CKA_LABEL);
                            attributes.Add(CKA.CKA_KEY_TYPE);

                            foundObjects = session.FindAllObjects(searchTemplate);
                            foreach (ObjectHandle foundObject in foundObjects)
                            {
                                j++;

                                objectAttributes = session.GetAttributeValue(foundObject, attributes);

                                pkcs11UriBuilder = new Pkcs11UriBuilder(pkcs11Uri);
                                pkcs11UriBuilder.Type = CKO.CKO_SECRET_KEY;
                                pkcs11UriBuilder.Id = objectAttributes[0].GetValueAsByteArray();
                                pkcs11UriBuilder.Object = objectAttributes[1].GetValueAsString();

                                Console.WriteLine("");
                                Console.WriteLine("Object no." + j);
                                Console.WriteLine("  CKA_CLASS:             CKO_SECRET_KEY");
                                Console.WriteLine("  CKA_ID:                " + ConvertUtils.BytesToHexString(pkcs11UriBuilder.Id));
                                Console.WriteLine("  CKA_LABEL:             " + pkcs11UriBuilder.Object);
                                Console.WriteLine("  CKA_KEY_TYPE:          " + ((CKK)objectAttributes[2].GetValueAsUlong()).ToString());
                                Console.WriteLine("  PKCS#11 URI:           " + pkcs11UriBuilder.ToString());
                            }

                            #endregion
                        }

                        Console.WriteLine();
                        Console.WriteLine(string.Format("Total number of listed objects: {0}", j));
                    }
                }

                #endregion
            }
            catch (Exception ex)
            {
                Console.WriteLine(@"Operation error: " + ex.GetType() + " - " + ex.Message);
                Console.WriteLine(ex.StackTrace);
                Environment.Exit(_exitError);
            }

            Environment.Exit(_exitSuccess);
        }

        /// <summary>
        /// Prints program usage and exits application
        /// </summary>
        /// <param name="error">Error message to be printed or null</param>
        static void ExitWithHelp(string error)
        {
            if (string.IsNullOrEmpty(error))
            {
                Console.WriteLine(@"Demonstration application for Pkcs11Interop.URI library");
                Console.WriteLine(@"Copyright (c) 2013-2015 JWC s.r.o. <http://www.jwc.sk>");
                Console.WriteLine(@"Author: Jaroslav Imrich <jimrich@jimrich.sk>");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine(@"Argument error: " + error);
                Console.WriteLine();
            }

            Console.WriteLine(@"Example usage:");
            Console.WriteLine();
            Console.WriteLine(@"  List available slots:");
            Console.WriteLine(@"    Pkcs11Interop.URI.Demo.exe");
            Console.WriteLine(@"      --uri <URI with module-path attribute>");
            Console.WriteLine(@"      --list-slots");
            Console.WriteLine();
            Console.WriteLine(@"  List available tokens:");
            Console.WriteLine(@"    Pkcs11Interop.URI.Demo.exe");
            Console.WriteLine(@"      --uri <URI with module-path attribute>");
            Console.WriteLine(@"      --list-tokens");
            Console.WriteLine();
            Console.WriteLine(@"  List storage objects available on specified token:");
            Console.WriteLine(@"    Pkcs11Interop.URI.Demo.exe");
            Console.WriteLine(@"      --uri <URI with module-path attribute>");
            Console.WriteLine(@"      --list-objects");

            Environment.Exit((string.IsNullOrEmpty(error)) ? _exitSuccess : _exitError);
        }
    }
}
