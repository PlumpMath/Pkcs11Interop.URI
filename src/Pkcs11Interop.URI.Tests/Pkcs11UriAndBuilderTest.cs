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
using NUnit.Framework;

namespace Net.Pkcs11Interop.URI.Tests
{
    /// <summary>
    /// Unit tests that verify Pkcs11Uri and Pkcs11UriBuilder implementation
    /// </summary>
    [TestFixture()]
    public class Pkcs11UriAndBuilderTest
    {
        #region Private variables

        private static string _pk11PathChars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:[]@!$'()*+,=&";

        private static string _pk11QueryChars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:[]@!$'()*+,=/?";

        private static string _pk11VendorAttrNameChars = @"_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        private static string _pctEncodedUnicodeChar = @"%C3%A4";

        private static string _unicodeChar = ConvertUtils.BytesToUtf8String(new byte[] { 0xc3, 0xa4 });

        #endregion

        #region General uri processing

        [Test()]
        public void NullUri()
        {
            string uri = null;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }
        }

        [Test()]
        public void EmptyUri()
        {
            string uri = string.Empty;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentNullException);
            }
        }

        [Test()]
        public void HttpUri()
        {
            string uri = @"http://www.pkcs11interop.net/";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void StringWithoutUri()
        {
            string uri = @"foobar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void UriWithoutAttributes()
        {
            string uri = @"pkcs11:";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes == null);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes == null);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == null);
            Assert.IsTrue(pkcs11uri.LibraryDescription == null);
            Assert.IsTrue(pkcs11uri.LibraryVersion == null);
            Assert.IsTrue(pkcs11uri.SlotManufacturer == null);
            Assert.IsTrue(pkcs11uri.SlotDescription == null);
            Assert.IsTrue(pkcs11uri.SlotId == null);
            Assert.IsTrue(pkcs11uri.Manufacturer == null);
            Assert.IsTrue(pkcs11uri.Model == null);
            Assert.IsTrue(pkcs11uri.Serial == null);
            Assert.IsTrue(pkcs11uri.Token == null);
            Assert.IsTrue(pkcs11uri.Type == null);
            Assert.IsTrue(pkcs11uri.Object == null);
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, null));
            Assert.IsTrue(pkcs11uri.ModulePath == null);
            Assert.IsTrue(pkcs11uri.ModuleName == null);
            Assert.IsTrue(pkcs11uri.PinValue == null);
            Assert.IsTrue(pkcs11uri.PinSource == null);
        }

        [Test()]
        public void UriWithAllKnownAttributes()
        {
            string uri = @"pkcs11:";
            uri += @"library-manufacturer=foo;library-description=bar;library-version=1;";
            uri += @"slot-manufacturer=foo;slot-description=bar;slot-id=1;";
            uri += @"manufacturer=foo;model=bar;serial=foo;token=bar;";
            uri += @"type=private;object=foo;id=%62%61%72";
            uri += @"?";
            uri += @"module-path=foo&module-name=bar&";
            uri += @"pin-value=foo&pin-source=bar";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.LibraryManufacturer = "foo";
            pkcs11UriBuilder.LibraryDescription = "bar";
            pkcs11UriBuilder.LibraryVersion = "1";
            pkcs11UriBuilder.SlotManufacturer = "foo";
            pkcs11UriBuilder.SlotDescription = "bar";
            pkcs11UriBuilder.SlotId = 1;
            pkcs11UriBuilder.Manufacturer = "foo";
            pkcs11UriBuilder.Model = "bar";
            pkcs11UriBuilder.Serial = "foo";
            pkcs11UriBuilder.Token = "bar";
            pkcs11UriBuilder.Type = CKO.CKO_PRIVATE_KEY;
            pkcs11UriBuilder.Object = "foo";
            pkcs11UriBuilder.Id = ConvertUtils.Utf8StringToBytes("bar");
            pkcs11UriBuilder.ModulePath = "foo";
            pkcs11UriBuilder.ModuleName = "bar";
            pkcs11UriBuilder.PinValue = "foo";
            pkcs11UriBuilder.PinSource = "bar";
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes == null);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes == null);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.LibraryDescription == "bar");
            Assert.IsTrue(pkcs11uri.LibraryVersion == "1.0");
            Assert.IsTrue(pkcs11uri.SlotManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.SlotDescription == "bar");
            Assert.IsTrue(pkcs11uri.SlotId == 1);
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
            Assert.IsTrue(pkcs11uri.ModulePath == "foo");
            Assert.IsTrue(pkcs11uri.ModuleName == "bar");
            Assert.IsTrue(pkcs11uri.PinValue == "foo");
            Assert.IsTrue(pkcs11uri.PinSource == "bar");
        }

        [Test()]
        public void UriWithoutPathAttributes()
        {
            string uri = @"pkcs11:";
            uri += @"?";
            uri += @"module-path=foo&module-name=bar&";
            uri += @"pin-value=foo&pin-source=bar";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.ModulePath = "foo";
            pkcs11UriBuilder.ModuleName = "bar";
            pkcs11UriBuilder.PinValue = "foo";
            pkcs11UriBuilder.PinSource = "bar";
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes == null);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes == null);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == null);
            Assert.IsTrue(pkcs11uri.LibraryDescription == null);
            Assert.IsTrue(pkcs11uri.LibraryVersion == null);
            Assert.IsTrue(pkcs11uri.SlotManufacturer == null);
            Assert.IsTrue(pkcs11uri.SlotDescription == null);
            Assert.IsTrue(pkcs11uri.SlotId == null);
            Assert.IsTrue(pkcs11uri.Manufacturer == null);
            Assert.IsTrue(pkcs11uri.Model == null);
            Assert.IsTrue(pkcs11uri.Serial == null);
            Assert.IsTrue(pkcs11uri.Token == null);
            Assert.IsTrue(pkcs11uri.Type == null);
            Assert.IsTrue(pkcs11uri.Object == null);
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, null));
            Assert.IsTrue(pkcs11uri.ModulePath == "foo");
            Assert.IsTrue(pkcs11uri.ModuleName == "bar");
            Assert.IsTrue(pkcs11uri.PinValue == "foo");
            Assert.IsTrue(pkcs11uri.PinSource == "bar");
        }

        [Test()]
        public void UriWithoutQueryAttributes()
        {
            string uri = @"pkcs11:";
            uri += @"library-manufacturer=foo;library-description=bar;library-version=1;";
            uri += @"slot-manufacturer=foo;slot-description=bar;slot-id=1;";
            uri += @"manufacturer=foo;model=bar;serial=foo;token=bar;";
            uri += @"type=private;object=foo;id=%62%61%72";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.LibraryManufacturer = "foo";
            pkcs11UriBuilder.LibraryDescription = "bar";
            pkcs11UriBuilder.LibraryVersion = "1";
            pkcs11UriBuilder.SlotManufacturer = "foo";
            pkcs11UriBuilder.SlotDescription = "bar";
            pkcs11UriBuilder.SlotId = 1;
            pkcs11UriBuilder.Manufacturer = "foo";
            pkcs11UriBuilder.Model = "bar";
            pkcs11UriBuilder.Serial = "foo";
            pkcs11UriBuilder.Token = "bar";
            pkcs11UriBuilder.Type = CKO.CKO_PRIVATE_KEY;
            pkcs11UriBuilder.Object = "foo";
            pkcs11UriBuilder.Id = ConvertUtils.Utf8StringToBytes("bar");
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes == null);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes == null);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.LibraryDescription == "bar");
            Assert.IsTrue(pkcs11uri.LibraryVersion == "1.0");
            Assert.IsTrue(pkcs11uri.SlotManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.SlotDescription == "bar");
            Assert.IsTrue(pkcs11uri.SlotId == 1);
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
            Assert.IsTrue(pkcs11uri.ModulePath == null);
            Assert.IsTrue(pkcs11uri.ModuleName == null);
            Assert.IsTrue(pkcs11uri.PinValue == null);
            Assert.IsTrue(pkcs11uri.PinSource == null);
        }

        [Test()]
        public void UriWithEmptyQuery()
        {
            string uri = @"pkcs11:";
            uri += @"library-manufacturer=foo;library-description=bar;library-version=1;";
            uri += @"manufacturer=foo;model=bar;serial=foo;token=bar;";
            uri += @"type=private;object=foo;id=%62%61%72?";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void PathAttributeWithoutEqualsChar()
        {
            string uri = @"pkcs11:library-manufacturer";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void QueryAttributeWithoutEqualsChar()
        {
            string uri = @"pkcs11:?pin-source";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Uri extraction

        [Test()]
        public void UriWithWhiteSpaces()
        {
            string uri = @"pkcs11:
library-manufacturer=foo;                library-description=bar;library-version=1;
slot-manufacturer=foo;slot-description=bar;slot-id=1;                 

manufacturer=foo;model=bar; serial=foo;token=bar;
type=private;object=foo;id=%62%61%72    ?    module-path=foo&module-name=bar&pin-value=foo&pin-source=bar";

            // Note: Builder cannot be used to produce URI like this one

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes == null);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes == null);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.LibraryDescription == "bar");
            Assert.IsTrue(pkcs11uri.LibraryVersion == "1.0");
            Assert.IsTrue(pkcs11uri.SlotManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.SlotDescription == "bar");
            Assert.IsTrue(pkcs11uri.SlotId == 1);
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
            Assert.IsTrue(pkcs11uri.ModulePath == "foo");
            Assert.IsTrue(pkcs11uri.ModuleName == "bar");
            Assert.IsTrue(pkcs11uri.PinValue == "foo");
            Assert.IsTrue(pkcs11uri.PinSource == "bar");
        }

        [Test()]
        public void UriEnclosedByAngleBrackets()
        {
            string uri = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum ut ipsum pretium,
faucibus diam quis, hendrerit leo. Maecenas aliquam elit lectus, pulvinar accumsan dui
egestas et. Duis tincidunt ut magna nec tincidunt. In vitae arcu convallis, tempus nisl
id, tincidunt eros. Ut tristique, nisi eget suscipit mollis, diam quam vehicula risus, 
eget tristique nunc est dapibus dolor. Vestibulum vehicula vel velit luctus tincidunt. 
<pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;
slot-manufacturer=foo;slot-description=bar;slot-id=1;manufacturer
=foo;model=bar;serial=foo;token=bar;type=private;object=foo;id=%62%61%72?module-path
=foo&module-name=bar&pin-value=foo&pin-source=bar> In volutpat laoreet auctor. Nam 
convallis dignissim purus, non posuere leo sagittis sed. Proin non mi ante. Duis eu 
egestas nisl. Quisque non egestas turpis, nec tincidunt mauris. Pellentesque elementum 
sollicitudin bibendum.";

            // Note: Builder cannot be used to produce URI like this one

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes == null);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes == null);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.LibraryDescription == "bar");
            Assert.IsTrue(pkcs11uri.LibraryVersion == "1.0");
            Assert.IsTrue(pkcs11uri.SlotManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.SlotDescription == "bar");
            Assert.IsTrue(pkcs11uri.SlotId == 1);
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
            Assert.IsTrue(pkcs11uri.ModulePath == "foo");
            Assert.IsTrue(pkcs11uri.ModuleName == "bar");
            Assert.IsTrue(pkcs11uri.PinValue == "foo");
            Assert.IsTrue(pkcs11uri.PinSource == "bar");
        }

        [Test()]
        public void UriEnclosedByQuotes()
        {
            string uri = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum ut ipsum pretium,
faucibus diam quis, hendrerit leo. Maecenas aliquam elit lectus, pulvinar accumsan dui
egestas et. Duis tincidunt ut magna nec tincidunt. In vitae arcu convallis, tempus nisl
id, tincidunt eros. Ut tristique, nisi eget suscipit mollis, diam quam vehicula risus, 
eget tristique nunc est dapibus dolor. Vestibulum vehicula vel velit luctus tincidunt. 
""pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;
slot-manufacturer=foo;slot-description=bar;slot-id=1;manufacturer
=foo;model=bar;serial=foo;token=bar;type=private;object=foo;id=%62%61%72?module-path
=foo&module-name=bar&pin-value=foo&pin-source=bar"" In volutpat laoreet auctor. Nam 
convallis dignissim purus, non posuere leo sagittis sed. Proin non mi ante. Duis eu 
egestas nisl. Quisque non egestas turpis, nec tincidunt mauris. Pellentesque elementum 
sollicitudin bibendum.";

            // Note: Builder cannot be used to produce URI like this one

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes == null);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes == null);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.LibraryDescription == "bar");
            Assert.IsTrue(pkcs11uri.LibraryVersion == "1.0");
            Assert.IsTrue(pkcs11uri.SlotManufacturer == "foo");
            Assert.IsTrue(pkcs11uri.SlotDescription == "bar");
            Assert.IsTrue(pkcs11uri.SlotId == 1);
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
            Assert.IsTrue(pkcs11uri.ModulePath == "foo");
            Assert.IsTrue(pkcs11uri.ModuleName == "bar");
            Assert.IsTrue(pkcs11uri.PinValue == "foo");
            Assert.IsTrue(pkcs11uri.PinSource == "bar");
        }

        [Test()]
        public void UnenclosedUri()
        {
            string uri = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum ut ipsum pretium,
faucibus diam quis, hendrerit leo. Maecenas aliquam elit lectus, pulvinar accumsan dui
egestas et. Duis tincidunt ut magna nec tincidunt. In vitae arcu convallis, tempus nisl
id, tincidunt eros. Ut tristique, nisi eget suscipit mollis, diam quam vehicula risus, 
eget tristique nunc est dapibus dolor. Vestibulum vehicula vel velit luctus tincidunt. 
pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;
slot-manufacturer=foo;slot-description=bar;slot-id=1;manufacturer
=foo;model=bar;serial=foo;token=bar;type=private;object=foo;id=%62%61%72?module-path
=foo&module-name=bar&pin-value=foo&pin-source=bar In volutpat laoreet auctor. Nam 
convallis dignissim purus, non posuere leo sagittis sed. Proin non mi ante. Duis eu 
egestas nisl. Quisque non egestas turpis, nec tincidunt mauris. Pellentesque elementum 
sollicitudin bibendum.";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Path attributes parsing

        #region Token

        [Test()]
        public void TokenWithValidValue()
        {
            string uri = @"pkcs11:token=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.Token = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Token == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void TokenWithInvalidValue()
        {
            string uri = @"pkcs11:token=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void TokenWithoutValue()
        {
            string uri = @"pkcs11:token=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Token = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Token == string.Empty);
        }

        [Test()]
        public void TokenWithMultipleValues()
        {
            string uri = @"pkcs11:token=foo;token=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Manufacturer
        
        [Test()]
        public void ManufacturerWithValidValue()
        {
            string uri = @"pkcs11:manufacturer=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.Manufacturer = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Manufacturer == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Manufacturer = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ManufacturerWithInvalidValue()
        {
            string uri = @"pkcs11:manufacturer=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ManufacturerWithoutValue()
        {
            string uri = @"pkcs11:manufacturer=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Manufacturer = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Manufacturer == string.Empty);
        }

        [Test()]
        public void ManufacturerWithMultipleValues()
        {
            string uri = @"pkcs11:manufacturer=foo;manufacturer=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Serial

        [Test()]
        public void SerialWithValidValue()
        {
            string uri = @"pkcs11:serial=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.Serial = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Serial == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Serial = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SerialWithInvalidValue()
        {
            string uri = @"pkcs11:serial=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SerialWithoutValue()
        {
            string uri = @"pkcs11:serial=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Serial = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Serial == string.Empty);
        }

        [Test()]
        public void SerialWithMultipleValues()
        {
            string uri = @"pkcs11:serial=foo;serial=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Model

        [Test()]
        public void ModelWithValidValue()
        {
            string uri = @"pkcs11:model=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.Model = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Model == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Model = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ModelWithInvalidValue()
        {
            string uri = @"pkcs11:model=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ModelWithoutValue()
        {
            string uri = @"pkcs11:model=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Model = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == true);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.Model == string.Empty);
        }

        [Test()]
        public void ModelWithMultipleValues()
        {
            string uri = @"pkcs11:model=foo;model=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion
        
        #region LibraryManufacturer

        [Test()]
        public void LibraryManufacturerWithValidValue()
        {
            string uri = @"pkcs11:library-manufacturer=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.LibraryManufacturer = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryManufacturerWithInvalidValue()
        {
            string uri = @"pkcs11:library-manufacturer=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryManufacturerWithoutValue()
        {
            string uri = @"pkcs11:library-manufacturer=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.LibraryManufacturer = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.LibraryManufacturer == string.Empty);
        }

        [Test()]
        public void LibraryManufacturerWithMultipleValues()
        {
            string uri = @"pkcs11:library-manufacturer=foo;library-manufacturer=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region LibraryDescription

        [Test()]
        public void LibraryDescriptionWithValidValue()
        {
            string uri = @"pkcs11:library-description=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.LibraryDescription = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.LibraryDescription == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryDescription = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryDescriptionWithInvalidValue()
        {
            string uri = @"pkcs11:library-description=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryDescriptionWithoutValue()
        {
            string uri = @"pkcs11:library-description=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.LibraryDescription = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.LibraryDescription == string.Empty);
        }

        [Test()]
        public void LibraryDescriptionWithMultipleValues()
        {
            string uri = @"pkcs11:library-description=foo;library-description=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region LibraryVersion
        
        [Test()]
        public void LibraryVersionWithValidValue()
        {
            string uri = @"pkcs11:library-version=1.256";

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.LibraryVersion = "1.256";
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.LibraryVersion == "1.256");

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryVersion = "1.256";
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryVersionWithInvalidValue()
        {
            string uri = @"pkcs11:library-version=x.y";

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryVersion = "x.y";
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryVersionWithoutValue()
        {
            string uri = @"pkcs11:library-version=";

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryVersion = string.Empty;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryVersionWithoutMajorPart()
        {
            string uri = @"pkcs11:library-version=.1";

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryVersion = ".1";
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryVersionWithoutMinorPart()
        {
            string uri = @"pkcs11:library-version=1";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.LibraryVersion = "1";
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == true);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.LibraryVersion == "1.0");
        }

        [Test()]
        public void LibraryVersionWithDotWithoutMinorPart()
        {
            string uri = @"pkcs11:library-version=1.";

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryVersion = "1.";
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryVersionWithTwoDots()
        {
            string uri = @"pkcs11:library-version=1.2.3";

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryVersion = "1.2.3";
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void LibraryVersionWithMultipleValues()
        {
            string uri = @"pkcs11:library-version=1.0;library-version=2.0";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region SlotManufacturer

        [Test()]
        public void SlotManufacturerWithValidValue()
        {
            string uri = @"pkcs11:slot-manufacturer=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.SlotManufacturer = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.SlotManufacturer == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SlotManufacturerWithInvalidValue()
        {
            string uri = @"pkcs11:slot-manufacturer=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SlotManufacturerWithoutValue()
        {
            string uri = @"pkcs11:slot-manufacturer=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.SlotManufacturer = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.SlotManufacturer == string.Empty);
        }

        [Test()]
        public void SlotManufacturerWithMultipleValues()
        {
            string uri = @"pkcs11:slot-manufacturer=foo;slot-manufacturer=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region SlotDescription

        [Test()]
        public void SlotDescriptionWithValidValue()
        {
            string uri = @"pkcs11:slot-description=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.SlotDescription = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.SlotDescription == _pk11PathChars + _unicodeChar);

            try
            {
                // Build URI with length checking
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotDescription = _pk11PathChars + _unicodeChar;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is ArgumentOutOfRangeException);
            }

            try
            {
                // Parse URI with length checking
                pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SlotDescriptionWithInvalidValue()
        {
            string uri = @"pkcs11:slot-description=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SlotDescriptionWithoutValue()
        {
            string uri = @"pkcs11:slot-description=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.SlotDescription = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.SlotDescription == string.Empty);
        }

        [Test()]
        public void SlotDescriptionWithMultipleValues()
        {
            string uri = @"pkcs11:slot-description=foo;slot-description=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region SlotId

        [Test()]
        public void SlotIdWithValidValue()
        {
            string uri = @"pkcs11:slot-id=18446744073709551615";

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.SlotId = 18446744073709551615;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.SlotId == 18446744073709551615);

            // Build URI with length checking
            pkcs11UriBuilder = new Pkcs11UriBuilder(true);
            pkcs11UriBuilder.SlotId = 18446744073709551615;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI with length checking
            pkcs11uri = new Pkcs11Uri(uri, true);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == true);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.SlotId == 18446744073709551615);
        }

        [Test()]
        public void SlotIdWithInvalidValue()
        {
            string uri = @"pkcs11:slot-id=foo";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            uri = @"pkcs11:slot-id=18446744073709551616";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SlotIdWithoutValue()
        {
            string uri = @"pkcs11:slot-id=";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void SlotIdWithMultipleValues()
        {
            string uri = @"pkcs11:slot-id=1;slot-id=2";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Object

        [Test()]
        public void ObjectDescriptionWithValidValue()
        {
            string uri = @"pkcs11:object=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.Object = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.Object == _pk11PathChars + _unicodeChar);

            // Build URI with length checking
            pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Object = _pk11PathChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI with length checking
            pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.Object == _pk11PathChars + _unicodeChar);
        }

        [Test()]
        public void ObjectWithInvalidValue()
        {
            string uri = @"pkcs11:object=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ObjectWithoutValue()
        {
            string uri = @"pkcs11:object=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Object = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.Object == string.Empty);
        }

        [Test()]
        public void ObjectWithMultipleValues()
        {
            string uri = @"pkcs11:object=foo;object=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Type

        [Test()]
        public void KnownTypes()
        {
            string[] uris = new string[]
            {
                @"pkcs11:type=public",
                @"pkcs11:type=private",
                @"pkcs11:type=cert",
                @"pkcs11:type=secret-key",
                @"pkcs11:type=data"
            };

            foreach (string uri in uris)
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
                Assert.IsTrue(pkcs11uri.DefinesSlot == false);
                Assert.IsTrue(pkcs11uri.DefinesToken == false);
                Assert.IsTrue(pkcs11uri.DefinesObject == true);
                Assert.IsTrue(pkcs11uri.Type != null);

                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Type = pkcs11uri.Type;
                Assert.IsTrue(uri == pkcs11UriBuilder.ToString());
            }
        }

        [Test()]
        public void UnknownType()
        {
            string uri = @"pkcs11:type=otp";

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Type = CKO.CKO_OTP_KEY;
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void TypeWithoutValue()
        {
            string uri = @"pkcs11:type=";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void TypeWithMultipleValues()
        {
            string uri = @"pkcs11:type=public;type=private";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Id

        [Test()]
        public void IdWithValidValue()
        {
            string uri = @"pkcs11:id=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar)));

            uri = @"pkcs11:id=%41%42%43%44%45%46%47%48%49%4A%4B%4C%4D%4E%4F%50%51%52%53%54%55%56%57%58%59%5A%61%62%63%64%65%66%67%68%69%6A%6B%6C%6D%6E%6F%70%71%72%73%74%75%76%77%78%79%7A%30%31%32%33%34%35%36%37%38%39%2D%2E%5F%7E%3A%5B%5D%40%21%24%27%28%29%2A%2B%2C%3D%26%C3%A4";

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.Id = ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar)));

            // Build URI with length checking
            pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Id = ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI with length checking
            pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(Helpers.ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar)));
        }

        [Test()]
        public void IdWithInvalidValue()
        {
            string uri = @"pkcs11:id=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void IdWithInvalidFirstCharInPctEncoding()
        {
            string uri = @"pkcs11:id=%x1";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void IdWithInvalidSecondCharInPctEncoding()
        {
            string uri = @"pkcs11:id=%1x";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void IdWithMissingCharsInPctEncoding()
        {
            string uri = @"pkcs11:id=%";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }
        
        [Test()]
        public void IdWithoutValue()
        {
            string uri = @"pkcs11:id=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Id = new byte[0];
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(pkcs11uri.Id != null && pkcs11uri.Id.Length == 0);
        }

        [Test()]
        public void IdWithMultipleValues()
        {
            string uri = @"pkcs11:id=%01%02%03;id=%04%05%06";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Unknown vendor specific path attribute

        [Test()]
        public void VendorSpecificPathAttributeWithIncompleteName()
        {
            string uri = @"pkcs11:=" + _pk11PathChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
                pkcs11UriBuilder.UnknownPathAttributes.Add(string.Empty, _pk11PathChars + _unicodeChar);
                Assert.IsTrue(uri == pkcs11UriBuilder.ToString());
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void VendorSpecificPathAttributeWithInvalidName()
        {
            string uri = @"pkcs11:.=" + _pk11PathChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
                pkcs11UriBuilder.UnknownPathAttributes.Add(".", _pk11PathChars + _unicodeChar);
                Assert.IsTrue(uri == pkcs11UriBuilder.ToString());
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void VendorSpecificPathAttributeWithValidNameAndValue()
        {
            string uri = @"pkcs11:" + _pk11VendorAttrNameChars + "=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
            pkcs11UriBuilder.UnknownPathAttributes.Add(_pk11VendorAttrNameChars, _pk11PathChars + _unicodeChar);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes != null && pkcs11uri.UnknownPathAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes[_pk11VendorAttrNameChars] == _pk11PathChars + _unicodeChar);
        }
        
        [Test()]
        public void VendorSpecificPathAttributeWithInvalidValue()
        {
            string uri = @"pkcs11:vendor=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void VendorSpecificPathAttributeWithoutValue()
        {
            string uri = @"pkcs11:vendor=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
            pkcs11UriBuilder.UnknownPathAttributes.Add("vendor", string.Empty);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes != null && pkcs11uri.UnknownPathAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes["vendor"] == string.Empty);
        }

        [Test()]
        public void VendorSpecificPathAttributeWithMultipleValues()
        {
            string uri = @"pkcs11:vendor=foo;vendor=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #endregion

        #region Query attributes parsing

        #region PinSource

        [Test()]
        public void PinSourceWithValidValue()
        {
            string uri = @"pkcs11:?pin-source=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.PinSource = _pk11QueryChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.PinSource == _pk11QueryChars + _unicodeChar);
        }

        [Test()]
        public void PinSourceWithInvalidValue()
        {
            string uri = @"pkcs11:?pin-source=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void PinSourceWithoutValue()
        {
            string uri = @"pkcs11:?pin-source=";
            
            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.PinSource = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.PinSource == string.Empty);
        }

        [Test()]
        public void PinSourceWithMultipleValues()
        {
            string uri = @"pkcs11:?pin-source=foo&pin-source=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region PinValue

        [Test()]
        public void PinValueWithValidValue()
        {
            string uri = @"pkcs11:?pin-value=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.PinValue = _pk11QueryChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.PinValue == _pk11QueryChars + _unicodeChar);
        }

        [Test()]
        public void PinValueWithInvalidValue()
        {
            string uri = @"pkcs11:?pin-value=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void PinValueWithoutValue()
        {
            string uri = @"pkcs11:?pin-value=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.PinValue = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.PinValue == string.Empty);
        }

        [Test()]
        public void PinValueWithMultipleValues()
        {
            string uri = @"pkcs11:?pin-value=foo&pin-value=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region ModuleName

        [Test()]
        public void ModuleNameWithValidValue()
        {
            string uri = @"pkcs11:?module-name=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.ModuleName = _pk11QueryChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.ModuleName == _pk11QueryChars + _unicodeChar);
        }

        [Test()]
        public void ModuleNameWithInvalidValue()
        {
            string uri = @"pkcs11:?module-name=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ModuleNameWithoutValue()
        {
            string uri = @"pkcs11:?module-name=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.ModuleName = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.ModuleName == string.Empty);
        }

        [Test()]
        public void ModuleNameWithMultipleValues()
        {
            string uri = @"pkcs11:?module-name=foo&module-name=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region ModulePath

        [Test()]
        public void ModulePathWithValidValue()
        {
            string uri = @"pkcs11:?module-path=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.ModulePath = _pk11QueryChars + _unicodeChar;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.ModulePath == _pk11QueryChars + _unicodeChar);
        }

        [Test()]
        public void ModulePathWithInvalidValue()
        {
            string uri = @"pkcs11:?module-path=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ModulePathWithoutValue()
        {
            string uri = @"pkcs11:?module-path=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.ModulePath = string.Empty;
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.ModulePath == string.Empty);
        }

        [Test()]
        public void ModulePathWithMultipleValues()
        {
            string uri = @"pkcs11:?module-path=foo&module-path=bar";

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region Unknown vendor specific query attribute

        [Test()]
        public void VendorSpecificQueryAttributeWithIncompleteName()
        {
            string uri = @"pkcs11:?=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
                pkcs11UriBuilder.UnknownQueryAttributes.Add(string.Empty, new List<string> { _pk11QueryChars + _unicodeChar });
                Assert.IsTrue(uri == pkcs11UriBuilder.ToString());
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void VendorSpecificQueryAttributeWithInvalidName()
        {
            string uri = @"pkcs11:?.=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
                pkcs11UriBuilder.UnknownQueryAttributes.Add(".", new List<string> { _pk11QueryChars + _unicodeChar });
                Assert.IsTrue(uri == pkcs11UriBuilder.ToString());
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void VendorSpecificQueryAttributeWithValidNameAndValue()
        {
            string uri = @"pkcs11:?" + _pk11VendorAttrNameChars + "=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
            pkcs11UriBuilder.UnknownQueryAttributes.Add(_pk11VendorAttrNameChars, new List<string> { _pk11QueryChars + _unicodeChar });
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes != null && pkcs11uri.UnknownQueryAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes[_pk11VendorAttrNameChars].Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes[_pk11VendorAttrNameChars][0] == _pk11QueryChars + _unicodeChar);
        }

        [Test()]
        public void VendorSpecificQueryAttributeWithInvalidValue()
        {
            string uri = @"pkcs11:?vendor=foobar" + _unicodeChar;

            // Note: Builder cannot be used to produce URI like this one

            try
            {
                // Parse URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void VendorSpecificQueryAttributeWithoutValue()
        {
            string uri = @"pkcs11:?vendor=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
            pkcs11UriBuilder.UnknownQueryAttributes.Add("vendor", new List<string> { string.Empty });
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesSlot == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes != null && pkcs11uri.UnknownQueryAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["vendor"].Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["vendor"][0] == string.Empty);
        }

        [Test()]
        public void VendorSpecificQueryAttributeWithMultipleValues()
        {
            string uri = @"pkcs11:?vendor=foo&vendor=bar";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
            pkcs11UriBuilder.UnknownQueryAttributes.Add("vendor", new List<string> { "foo", "bar" });
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes != null && pkcs11uri.UnknownQueryAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["vendor"].Count == 2);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["vendor"][0] == "foo");
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["vendor"][1] == "bar");
        }

        #endregion
        
        #endregion
    }
}
