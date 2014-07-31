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
using NUnit.Framework;
using HLA = Net.Pkcs11Interop.HighLevelAPI;
using HLA4 = Net.Pkcs11Interop.HighLevelAPI4;
using HLA8 = Net.Pkcs11Interop.HighLevelAPI8;
using LLA4 = Net.Pkcs11Interop.LowLevelAPI4;
using LLA8 = Net.Pkcs11Interop.LowLevelAPI8;

namespace Net.Pkcs11Interop.URI.Tests
{
    /// <summary>
    /// Unit tests that verify Pkcs11Uri and Pkcs11UriBuilder implementation
    /// </summary>
    [TestFixture()]
    public class Pkcs11UriAndBuilderTest
    {
        #region Test settings

        /// <summary>
        /// Path to the unmanaged PKCS#11 library that should be used by unit tests
        /// </summary>
        private static string _pkcs11LibraryPath = @"siecap11.dll";

        #endregion

        #region Private variables

        private static string _pk11PathChars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:[]@!$'()*+,=&";

        private static string _pk11QueryChars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:[]@!$'()*+,=/?";

        private static string _pk11VendorAttrNameChars = @"_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        private static string _pctEncodedUnicodeChar = @"%C3%A4";

        private static string _unicodeChar = ConvertUtils.BytesToUtf8String(new byte[] { 0xc3, 0xa4 });

        #endregion

        #region Private helper methods

        private bool ByteArraysMatch(byte[] array1, byte[] array2)
        {
            if (array1 == null)
            {
                if (array2 != null)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            else
            {
                if (array2 == null)
                {
                    return false;
                }
                else
                {
                    if (array1.Length != array2.Length)
                        return false;

                    for (int i = 0; i < array1.Length; i++)
                    {
                        if (array1[i] != array2[i])
                            return false;
                    }

                    return true;
                }
            }
        }

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
            Assert.IsTrue(pkcs11uri.Manufacturer == null);
            Assert.IsTrue(pkcs11uri.Model == null);
            Assert.IsTrue(pkcs11uri.Serial == null);
            Assert.IsTrue(pkcs11uri.Token == null);
            Assert.IsTrue(pkcs11uri.Type == null);
            Assert.IsTrue(pkcs11uri.Object == null);
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, null));
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
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
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
            Assert.IsTrue(pkcs11uri.Manufacturer == null);
            Assert.IsTrue(pkcs11uri.Model == null);
            Assert.IsTrue(pkcs11uri.Serial == null);
            Assert.IsTrue(pkcs11uri.Token == null);
            Assert.IsTrue(pkcs11uri.Type == null);
            Assert.IsTrue(pkcs11uri.Object == null);
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, null));
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
            uri += @"manufacturer=foo;model=bar;serial=foo;token=bar;";
            uri += @"type=private;object=foo;id=%62%61%72";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.LibraryManufacturer = "foo";
            pkcs11UriBuilder.LibraryDescription = "bar";
            pkcs11UriBuilder.LibraryVersion = "1";
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
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
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
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
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
<pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;manufacturer
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
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
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
""pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;manufacturer
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
            Assert.IsTrue(pkcs11uri.Manufacturer == "foo");
            Assert.IsTrue(pkcs11uri.Model == "bar");
            Assert.IsTrue(pkcs11uri.Serial == "foo");
            Assert.IsTrue(pkcs11uri.Token == "bar");
            Assert.IsTrue(pkcs11uri.Type == CKO.CKO_PRIVATE_KEY);
            Assert.IsTrue(pkcs11uri.Object == "foo");
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes("bar")));
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
pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;manufacturer
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
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar)));

            uri = @"pkcs11:id=%41%42%43%44%45%46%47%48%49%4A%4B%4C%4D%4E%4F%50%51%52%53%54%55%56%57%58%59%5A%61%62%63%64%65%66%67%68%69%6A%6B%6C%6D%6E%6F%70%71%72%73%74%75%76%77%78%79%7A%30%31%32%33%34%35%36%37%38%39%2D%2E%5F%7E%3A%5B%5D%40%21%24%27%28%29%2A%2B%2C%3D%26%C3%A4";

            // Build URI without length checking
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder(false);
            pkcs11UriBuilder.Id = ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI without length checking
            pkcs11uri = new Pkcs11Uri(uri, false);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar)));

            // Build URI with length checking
            pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.Id = ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI with length checking
            pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == true);
            Assert.IsTrue(ByteArraysMatch(pkcs11uri.Id, ConvertUtils.Utf8StringToBytes(_pk11PathChars + _unicodeChar)));
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
            string uri = @"pkcs11:x-=" + _pk11PathChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
                pkcs11UriBuilder.UnknownPathAttributes.Add("x-", _pk11PathChars + _unicodeChar);
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
            string uri = @"pkcs11:x-.=" + _pk11PathChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
                pkcs11UriBuilder.UnknownPathAttributes.Add("x-.", _pk11PathChars + _unicodeChar);
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
            string uri = @"pkcs11:x-" + _pk11VendorAttrNameChars + "=" + _pk11PathChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
            pkcs11UriBuilder.UnknownPathAttributes.Add("x-" + _pk11VendorAttrNameChars, _pk11PathChars + _unicodeChar);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes != null && pkcs11uri.UnknownPathAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes["x-" + _pk11VendorAttrNameChars] == _pk11PathChars + _unicodeChar);
        }
        
        [Test()]
        public void VendorSpecificPathAttributeWithInvalidValue()
        {
            string uri = @"pkcs11:x-vendor=foobar" + _unicodeChar;

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
            string uri = @"pkcs11:x-vendor=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownPathAttributes = new Dictionary<string, string>();
            pkcs11UriBuilder.UnknownPathAttributes.Add("x-vendor", string.Empty);
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes != null && pkcs11uri.UnknownPathAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownPathAttributes["x-vendor"] == string.Empty);
        }

        [Test()]
        public void VendorSpecificPathAttributeWithMultipleValues()
        {
            string uri = @"pkcs11:x-vendor=foo;x-vendor=bar";

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

        #region Unknown path attribute

        [Test()]
        public void UnknownPathAttribute()
        {
            string uri = @"pkcs11:foo=bar";

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
            string uri = @"pkcs11:?x-=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
                pkcs11UriBuilder.UnknownQueryAttributes.Add("x-", new List<string> { _pk11QueryChars + _unicodeChar });
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
            string uri = @"pkcs11:?x-.=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            try
            {
                // Build URI
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
                pkcs11UriBuilder.UnknownQueryAttributes.Add("x-.", new List<string> { _pk11QueryChars + _unicodeChar });
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
            string uri = @"pkcs11:?x-" + _pk11VendorAttrNameChars + "=" + _pk11QueryChars + _pctEncodedUnicodeChar;

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
            pkcs11UriBuilder.UnknownQueryAttributes.Add("x-" + _pk11VendorAttrNameChars, new List<string> { _pk11QueryChars + _unicodeChar });
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes != null && pkcs11uri.UnknownQueryAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["x-" + _pk11VendorAttrNameChars].Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["x-" + _pk11VendorAttrNameChars][0] == _pk11QueryChars + _unicodeChar);

        }

        [Test()]
        public void VendorSpecificQueryAttributeWithInvalidValue()
        {
            string uri = @"pkcs11:?x-vendor=foobar" + _unicodeChar;

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
            string uri = @"pkcs11:?x-vendor=";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
            pkcs11UriBuilder.UnknownQueryAttributes.Add("x-vendor", new List<string> { string.Empty });
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes != null && pkcs11uri.UnknownQueryAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["x-vendor"].Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["x-vendor"][0] == string.Empty);
        }

        [Test()]
        public void VendorSpecificQueryAttributeWithMultipleValues()
        {
            string uri = @"pkcs11:?x-vendor=foo&x-vendor=bar";

            // Build URI
            Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
            pkcs11UriBuilder.UnknownQueryAttributes = new Dictionary<string, List<string>>();
            pkcs11UriBuilder.UnknownQueryAttributes.Add("x-vendor", new List<string> { "foo", "bar" });
            Assert.IsTrue(uri == pkcs11UriBuilder.ToString());

            // Parse URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);
            Assert.IsTrue(pkcs11uri.DefinesLibrary == false);
            Assert.IsTrue(pkcs11uri.DefinesToken == false);
            Assert.IsTrue(pkcs11uri.DefinesObject == false);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes != null && pkcs11uri.UnknownQueryAttributes.Count == 1);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["x-vendor"].Count == 2);
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["x-vendor"][0] == "foo");
            Assert.IsTrue(pkcs11uri.UnknownQueryAttributes["x-vendor"][1] == "bar");
        }

        #endregion

        #region Unknown query attribute

        [Test()]
        public void UnknownQueryAttribute()
        {
            string uri = @"pkcs11:?foo=bar";

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

        #region GetObjectAttributes for Pkcs11Interop

        [Test()]
        public void GetObjectAttributesHLA()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            List<HLA.ObjectAttribute> attributes = null;
            pkcs11uri.GetObjectAttributes(out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Count == 3);

            Assert.IsTrue(attributes[0].Type == (ulong)CKA.CKA_CLASS);
            Assert.IsTrue(attributes[0].GetValueAsUlong() == (ulong)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].Type == (ulong)CKA.CKA_LABEL);
            Assert.IsTrue(attributes[1].GetValueAsString() == "foo");

            Assert.IsTrue(attributes[2].Type == (ulong)CKA.CKA_ID);
            Assert.IsTrue(ByteArraysMatch(attributes[2].GetValueAsByteArray(), new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesHLA8()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            List<HLA8.ObjectAttribute> attributes = null;
            pkcs11uri.GetObjectAttributes(out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Count == 3);

            Assert.IsTrue(attributes[0].Type == (ulong)CKA.CKA_CLASS);
            Assert.IsTrue(attributes[0].GetValueAsUlong() == (ulong)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].Type == (ulong)CKA.CKA_LABEL);
            Assert.IsTrue(attributes[1].GetValueAsString() == "foo");

            Assert.IsTrue(attributes[2].Type == (ulong)CKA.CKA_ID);
            Assert.IsTrue(ByteArraysMatch(attributes[2].GetValueAsByteArray(), new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesHLA4()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            List<HLA4.ObjectAttribute> attributes = null;
            pkcs11uri.GetObjectAttributes(out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Count == 3);

            Assert.IsTrue(attributes[0].Type == (uint)CKA.CKA_CLASS);
            Assert.IsTrue(attributes[0].GetValueAsUint() == (uint)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].Type == (uint)CKA.CKA_LABEL);
            Assert.IsTrue(attributes[1].GetValueAsString() == "foo");

            Assert.IsTrue(attributes[2].Type == (uint)CKA.CKA_ID);
            Assert.IsTrue(ByteArraysMatch(attributes[2].GetValueAsByteArray(), new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesLLA8()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            LLA8.CK_ATTRIBUTE[] attributes = null;
            pkcs11uri.GetObjectAttributes(out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Length == 3);

            Assert.IsTrue(attributes[0].type == (uint)CKA.CKA_CLASS);
            ulong ckaClass = 0;
            LLA8.CkaUtils.ConvertValue(ref attributes[0], out ckaClass);
            Assert.IsTrue(ckaClass == (ulong)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].type == (uint)CKA.CKA_LABEL);
            string ckaLabel = null;
            LLA8.CkaUtils.ConvertValue(ref attributes[1], out ckaLabel);
            Assert.IsTrue(ckaLabel == "foo");

            Assert.IsTrue(attributes[2].type == (uint)CKA.CKA_ID);
            byte[] ckaId = null;
            LLA8.CkaUtils.ConvertValue(ref attributes[2], out ckaId);
            Assert.IsTrue(ByteArraysMatch(ckaId, new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesLLA4()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            LLA4.CK_ATTRIBUTE[] attributes = null;
            pkcs11uri.GetObjectAttributes(out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Length == 3);

            Assert.IsTrue(attributes[0].type == (uint)CKA.CKA_CLASS);
            uint ckaClass = 0;
            LLA4.CkaUtils.ConvertValue(ref attributes[0], out ckaClass);
            Assert.IsTrue(ckaClass == (uint)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].type == (uint)CKA.CKA_LABEL);
            string ckaLabel = null;
            LLA4.CkaUtils.ConvertValue(ref attributes[1], out ckaLabel);
            Assert.IsTrue(ckaLabel == "foo");

            Assert.IsTrue(attributes[2].type == (uint)CKA.CKA_ID);
            byte[] ckaId = null;
            LLA4.CkaUtils.ConvertValue(ref attributes[2], out ckaId);
            Assert.IsTrue(ByteArraysMatch(ckaId, new byte[] { 0x01, 0x02, 0x03 }));
        }

        #endregion

        #region Uri matching against Pkcs11Interop

        #region LibraryInfo

        [Test()]
        public void LibraryInfoMatchesHLA()
        {
            using (HLA.Pkcs11 pkcs11 = new HLA.Pkcs11(_pkcs11LibraryPath, false))
            {
                HLA.LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

                // LibraryManufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = "foobar";
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // LibraryDescription nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = "foobar";
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // LibraryVersion nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = "0";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));
            }
        }

        [Test()]
        public void LibraryInfoMatchesHLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (HLA8.Pkcs11 pkcs11 = new HLA8.Pkcs11(_pkcs11LibraryPath, false))
            {
                HLA8.LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

                // LibraryManufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = "foobar";
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // LibraryDescription nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = "foobar";
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // LibraryVersion nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = "0";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));
            }
        }

        [Test()]
        public void LibraryInfoMatchesHLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (HLA4.Pkcs11 pkcs11 = new HLA4.Pkcs11(_pkcs11LibraryPath, false))
            {
                HLA4.LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

                // LibraryManufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = "foobar";
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // LibraryDescription nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = "foobar";
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

                // LibraryVersion nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = "0";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(libraryInfo));
            }
        }

        [Test()]
        public void LibraryInfoMatchesLLA8()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            LLA8.CK_INFO libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("                                ");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;x-foo=bar");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

            // LibraryManufacturer nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

            // LibraryDescription nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

            // LibraryVersion nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x00 }, Minor = new byte[] { 0x01 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));
        }

        [Test()]
        public void LibraryInfoMatchesLLA4()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            LLA4.CK_INFO libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("                                ");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;x-foo=bar");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(pkcs11uri.Matches(libraryInfo));

            // LibraryManufacturer nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

            // LibraryDescription nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));

            // LibraryVersion nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x00 }, Minor = new byte[] { 0x01 } };
            Assert.IsFalse(pkcs11uri.Matches(libraryInfo));
        }

        #endregion

        #region TokenInfo

        [Test()]
        public void TokenInfoMatchesHLA()
        {
            using (HLA.Pkcs11 pkcs11 = new HLA.Pkcs11(_pkcs11LibraryPath, false))
            {
                List<HLA.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA.TokenInfo tokenInfo = slots[0].GetTokenInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

                // Token nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = "foobar";
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = "foobar";
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Serial nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Model nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));
            }
        }

        [Test()]
        public void TokenInfoMatchesHLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (HLA8.Pkcs11 pkcs11 = new HLA8.Pkcs11(_pkcs11LibraryPath, false))
            {
                List<HLA8.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA8.TokenInfo tokenInfo = slots[0].GetTokenInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

                // Token nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = "foobar";
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = "foobar";
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Serial nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Model nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));
            }
        }

        [Test()]
        public void TokenInfoMatchesHLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (HLA4.Pkcs11 pkcs11 = new HLA4.Pkcs11(_pkcs11LibraryPath, false))
            {
                List<HLA4.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA4.TokenInfo tokenInfo = slots[0].GetTokenInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

                // Token nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = "foobar";
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = "foobar";
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Serial nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

                // Model nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(pkcs11uri.Matches(tokenInfo));
            }
        }

        [Test()]
        public void TokenInfoMatchesLLA8()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            LLA8.CK_TOKEN_INFO tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("                                ");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar;x-foo=bar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

            // Label nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // ManufacturerId nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // SerialNumber nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("012");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // Model nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foo bar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));
        }

        [Test()]
        public void TokenInfoMatchesLLA4()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            LLA4.CK_TOKEN_INFO tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("                                ");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar;x-foo=bar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(pkcs11uri.Matches(tokenInfo));

            // Label nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // ManufacturerId nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // SerialNumber nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("012");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));

            // Model nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foo bar");
            Assert.IsFalse(pkcs11uri.Matches(tokenInfo));
        }

        #endregion

        #region ObjectAttributes

        [Test()]
        public void ObjectAttributesMatchesHLA()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            List<HLA.ObjectAttribute> objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;x-foo=bar");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA.ObjectAttribute>();
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Object present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA.ObjectAttribute>();
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Id present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA.ObjectAttribute>();
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ObjectAttributesMatchesHLA8()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            List<HLA8.ObjectAttribute> objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;x-foo=bar");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA8.ObjectAttribute>();
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Object present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA8.ObjectAttribute>();
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Id present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA8.ObjectAttribute>();
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ObjectAttributesMatchesHLA4()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            List<HLA4.ObjectAttribute> objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;x-foo=bar");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA4.ObjectAttribute>();
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Object present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA4.ObjectAttribute>();
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Id present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA4.ObjectAttribute>();
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ObjectAttributesMatchesLLA8()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            List<LLA8.CK_ATTRIBUTE> objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;x-foo=bar");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Object present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Id present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        [Test()]
        public void ObjectAttributesMatchesLLA4()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            List<LLA4.CK_ATTRIBUTE> objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;x-foo=bar");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(pkcs11uri.Matches(objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(pkcs11uri.Matches(objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Object present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }

            try
            {
                // Id present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
                pkcs11uri.Matches(objectAttributes);
                Assert.Fail("Exception expected but not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex is Pkcs11UriException);
            }
        }

        #endregion

        #region GetMatchingSlotList

        [Test()]
        public void GetMatchingSlotListHLA()
        {
            using (HLA.Pkcs11 pkcs11 = new HLA.Pkcs11(_pkcs11LibraryPath, false))
            {
                // Get all slots
                List<HLA.Slot> allSlots = pkcs11.GetSlotList(true);
                Assert.IsTrue(allSlots != null && allSlots.Count > 0);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                List<HLA.Slot> matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == allSlots.Count);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 0);

                // All attributes matching one slot
                HLA.LibraryInfo libraryInfo = pkcs11.GetInfo();
                HLA.TokenInfo tokenInfo = allSlots[0].GetTokenInfo();
                
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 0);
            }
        }

        [Test()]
        public void GetMatchingSlotListHLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (HLA8.Pkcs11 pkcs11 = new HLA8.Pkcs11(_pkcs11LibraryPath, false))
            {
                // Get all slots
                List<HLA8.Slot> allSlots = pkcs11.GetSlotList(true);
                Assert.IsTrue(allSlots != null && allSlots.Count > 0);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                List<HLA8.Slot> matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == allSlots.Count);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 0);

                // All attributes matching one slot
                HLA8.LibraryInfo libraryInfo = pkcs11.GetInfo();
                HLA8.TokenInfo tokenInfo = allSlots[0].GetTokenInfo();

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 0);
            }
        }

        [Test()]
        public void GetMatchingSlotListHLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (HLA4.Pkcs11 pkcs11 = new HLA4.Pkcs11(_pkcs11LibraryPath, false))
            {
                // Get all slots
                List<HLA4.Slot> allSlots = pkcs11.GetSlotList(true);
                Assert.IsTrue(allSlots != null && allSlots.Count > 0);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                List<HLA4.Slot> matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == allSlots.Count);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 0);

                // All attributes matching one slot
                HLA4.LibraryInfo libraryInfo = pkcs11.GetInfo();
                HLA4.TokenInfo tokenInfo = allSlots[0].GetTokenInfo();

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                matchedSlots = pkcs11uri.GetMatchingSlotList(pkcs11);
                Assert.IsTrue(matchedSlots.Count == 0);
            }
        }

        [Test()]
        public void GetMatchingSlotListLLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (LLA8.Pkcs11 pkcs11 = new LLA8.Pkcs11(_pkcs11LibraryPath, false))
            {
                CKR rv = pkcs11.C_Initialize(null);
                Assert.IsTrue(rv == CKR.CKR_OK);

                // Get all slots
                ulong allSlotsCount = 0;
                rv = pkcs11.C_GetSlotList(true, null, ref allSlotsCount);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(allSlotsCount > 0);
                ulong[] allSlots = new ulong[allSlotsCount];
                rv = pkcs11.C_GetSlotList(true, allSlots, ref allSlotsCount);
                Assert.IsTrue(rv == CKR.CKR_OK);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                ulong[] matchedSlots = null;
                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == allSlots.Length);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 0);

                // All attributes matching one slot
                LLA8.CK_INFO libraryInfo = new LLA8.CK_INFO();
                rv = pkcs11.C_GetInfo(ref libraryInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);
                LLA8.CK_TOKEN_INFO tokenInfo = new LLA8.CK_TOKEN_INFO();
                rv = pkcs11.C_GetTokenInfo(allSlots[0], ref tokenInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
                pkcs11UriBuilder.LibraryDescription = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
                pkcs11UriBuilder.LibraryVersion = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);
                pkcs11UriBuilder.Token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
                pkcs11UriBuilder.Manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
                pkcs11UriBuilder.Serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
                pkcs11UriBuilder.Model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 0);

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                Assert.IsTrue(rv == CKR.CKR_OK);
            }
        }

        [Test()]
        public void GetMatchingSlotListLLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (LLA4.Pkcs11 pkcs11 = new LLA4.Pkcs11(_pkcs11LibraryPath, false))
            {
                CKR rv = pkcs11.C_Initialize(null);
                Assert.IsTrue(rv == CKR.CKR_OK);

                // Get all slots
                uint allSlotsCount = 0;
                rv = pkcs11.C_GetSlotList(true, null, ref allSlotsCount);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(allSlotsCount > 0);
                uint[] allSlots = new uint[allSlotsCount];
                rv = pkcs11.C_GetSlotList(true, allSlots, ref allSlotsCount);
                Assert.IsTrue(rv == CKR.CKR_OK);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                uint[] matchedSlots = null;
                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == allSlots.Length);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:x-vendor=foobar");
                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 0);

                // All attributes matching one slot
                LLA4.CK_INFO libraryInfo = new LLA4.CK_INFO();
                rv = pkcs11.C_GetInfo(ref libraryInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);
                LLA4.CK_TOKEN_INFO tokenInfo = new LLA4.CK_TOKEN_INFO();
                rv = pkcs11.C_GetTokenInfo(allSlots[0], ref tokenInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
                pkcs11UriBuilder.LibraryDescription = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
                pkcs11UriBuilder.LibraryVersion = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);
                pkcs11UriBuilder.Token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
                pkcs11UriBuilder.Manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
                pkcs11UriBuilder.Serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
                pkcs11UriBuilder.Model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                rv = pkcs11uri.GetMatchingSlotList(pkcs11, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 0);

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                Assert.IsTrue(rv == CKR.CKR_OK);
            }
        }

        #endregion

        #endregion
    }
}
