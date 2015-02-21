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
using NUnit.Framework;
using HLA = Net.Pkcs11Interop.HighLevelAPI;
using HLA4 = Net.Pkcs11Interop.HighLevelAPI4;
using HLA8 = Net.Pkcs11Interop.HighLevelAPI8;
using LLA4 = Net.Pkcs11Interop.LowLevelAPI4;
using LLA8 = Net.Pkcs11Interop.LowLevelAPI8;

namespace Net.Pkcs11Interop.URI.Tests
{
    /// <summary>
    /// Unit tests that verify Pkcs11UriUtils implementation
    /// </summary>
    [TestFixture()]
    public class Pkcs11UriUtilsTest
    {
        #region PKCS#11 URI matching

        #region LibraryInfo

        [Test()]
        public void LibraryInfoMatchesHLA()
        {
            using (HLA.Pkcs11 pkcs11 = new HLA.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                HLA.LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryManufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = "foobar";
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryDescription nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = "foobar";
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryVersion nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = "0";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));
            }
        }

        [Test()]
        public void LibraryInfoMatchesHLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (HLA8.Pkcs11 pkcs11 = new HLA8.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                HLA8.LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryManufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = "foobar";
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryDescription nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = "foobar";
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryVersion nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = "0";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));
            }
        }

        [Test()]
        public void LibraryInfoMatchesHLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (HLA4.Pkcs11 pkcs11 = new HLA4.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                HLA4.LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryManufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = "foobar";
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryDescription nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = "foobar";
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

                // LibraryVersion nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = "0";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("                                ");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;foo=bar");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // LibraryManufacturer nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // LibraryDescription nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // LibraryVersion nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA8.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA8.CK_VERSION() { Major = new byte[] { 0x00 }, Minor = new byte[] { 0x01 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("                                ");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1;foo=bar");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // LibraryManufacturer nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // LibraryDescription nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x01 }, Minor = new byte[] { 0x00 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));

            // LibraryVersion nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:library-manufacturer=foo;library-description=bar;library-version=1");
            libraryInfo = new LLA4.CK_INFO();
            libraryInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            libraryInfo.LibraryDescription = ConvertUtils.Utf8StringToBytes("bar");
            libraryInfo.LibraryVersion = new LLA4.CK_VERSION() { Major = new byte[] { 0x00 }, Minor = new byte[] { 0x01 } };
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, libraryInfo));
        }

        #endregion

        #region SlotInfo

        [Test()]
        public void SlotInfoMatchesHLA()
        {
            using (HLA.Pkcs11 pkcs11 = new HLA.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                List<HLA.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA.SlotInfo slotInfo = slots[0].GetSlotInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = "foobar";
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Description nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = "foobar";
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Slot id nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId + 1;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));
            }
        }

        [Test()]
        public void SlotInfoMatchesHLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (HLA8.Pkcs11 pkcs11 = new HLA8.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                List<HLA8.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA8.SlotInfo slotInfo = slots[0].GetSlotInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = "foobar";
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Description nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = "foobar";
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Slot id nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId + 1;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));
            }
        }

        [Test()]
        public void SlotInfoMatchesHLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (HLA4.Pkcs11 pkcs11 = new HLA4.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                List<HLA4.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA4.SlotInfo slotInfo = slots[0].GetSlotInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = "foobar";
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Description nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = "foobar";
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));

                // Slot id nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId + 1;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo));
            }
        }

        [Test()]
        public void SlotInfoMatchesLLA8()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            LLA8.CK_SLOT_INFO slotInfo = new LLA8.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            ulong slotId = 1;
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=;slot-description=bar;slot-id=1");
            slotInfo = new LLA8.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("                                ");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1;foo=bar");
            slotInfo = new LLA8.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA8.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Manufacturer nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA8.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Description nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA8.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("foo");
            slotId = 1;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Slot id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA8.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 2;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));
        }

        [Test()]
        public void SlotInfoMatchesLLA4()
        {
            // Empty URI
            Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
            LLA4.CK_SLOT_INFO slotInfo = new LLA4.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            uint slotId = 1;
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=;slot-description=bar;slot-id=1");
            slotInfo = new LLA4.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("                                ");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1;foo=bar");
            slotInfo = new LLA4.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA4.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Manufacturer nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA4.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 1;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Description nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA4.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("foo");
            slotId = 1;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));

            // Slot id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:slot-manufacturer=foo;slot-description=bar;slot-id=1");
            slotInfo = new LLA4.CK_SLOT_INFO();
            slotInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            slotInfo.SlotDescription = ConvertUtils.Utf8StringToBytes("bar");
            slotId = 2;
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, slotInfo, slotId));
        }

        #endregion

        #region TokenInfo

        [Test()]
        public void TokenInfoMatchesHLA()
        {
            using (HLA.Pkcs11 pkcs11 = new HLA.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                List<HLA.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA.TokenInfo tokenInfo = slots[0].GetTokenInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Token nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = "foobar";
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = "foobar";
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Serial nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Model nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));
            }
        }

        [Test()]
        public void TokenInfoMatchesHLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (HLA8.Pkcs11 pkcs11 = new HLA8.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                List<HLA8.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA8.TokenInfo tokenInfo = slots[0].GetTokenInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Token nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = "foobar";
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = "foobar";
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Serial nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Model nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));
            }
        }

        [Test()]
        public void TokenInfoMatchesHLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (HLA4.Pkcs11 pkcs11 = new HLA4.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                List<HLA4.Slot> slots = pkcs11.GetSlotList(true);
                Assert.IsTrue(slots != null && slots.Count > 0);
                HLA4.TokenInfo tokenInfo = slots[0].GetTokenInfo();

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // All attributes matching
                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Token nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = "foobar";
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Manufacturer nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = "foobar";
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Serial nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

                // Model nonmatching
                pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("                                ");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar;foo=bar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Label nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // ManufacturerId nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // SerialNumber nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("012");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Model nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA8.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foo bar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("                                ");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar;foo=bar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Label nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // ManufacturerId nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // SerialNumber nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("012");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foobar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));

            // Model nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:token=foo;manufacturer=bar;serial=123;model=foobar");
            tokenInfo = new LLA4.CK_TOKEN_INFO();
            tokenInfo.Label = ConvertUtils.Utf8StringToBytes("foo");
            tokenInfo.ManufacturerId = ConvertUtils.Utf8StringToBytes("bar");
            tokenInfo.SerialNumber = ConvertUtils.Utf8StringToBytes("123");
            tokenInfo.Model = ConvertUtils.Utf8StringToBytes("foo bar");
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, tokenInfo));
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;foo=bar");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA.ObjectAttribute>();
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA.ObjectAttribute>();
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(new HLA.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;foo=bar");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA8.ObjectAttribute>();
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA8.ObjectAttribute>();
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(new HLA8.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;foo=bar");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<HLA4.ObjectAttribute>();
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<HLA4.ObjectAttribute>();
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(new HLA4.ObjectAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;foo=bar");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA8.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(LLA8.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Empty attribute
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, string.Empty));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Unknown path attribute in URI
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03;foo=bar");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // All attributes matching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsTrue(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Type nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Object nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foo bar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            // Id nonmatching
            pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
            objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
            objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x04, 0x05, 0x06 }));
            Assert.IsFalse(Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes));

            try
            {
                // Type present in URI but missing in list
                pkcs11uri = new Pkcs11Uri(@"pkcs11:type=private;object=foobar;id=%01%02%03");
                objectAttributes = new List<LLA4.CK_ATTRIBUTE>();
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_LABEL, "foobar"));
                objectAttributes.Add(LLA4.CkaUtils.CreateAttribute(CKA.CKA_ID, new byte[] { 0x01, 0x02, 0x03 }));
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
                Pkcs11UriUtils.Matches(pkcs11uri, objectAttributes);
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
            using (HLA.Pkcs11 pkcs11 = new HLA.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Get all slots
                List<HLA.Slot> allSlots = pkcs11.GetSlotList(true);
                Assert.IsTrue(allSlots != null && allSlots.Count > 0);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                List<HLA.Slot> matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == allSlots.Count);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 0);

                // All attributes matching one slot
                HLA.LibraryInfo libraryInfo = pkcs11.GetInfo();
                HLA.SlotInfo slotInfo = allSlots[0].GetSlotInfo();
                HLA.TokenInfo tokenInfo = allSlots[0].GetTokenInfo();

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 0);
            }
        }

        [Test()]
        public void GetMatchingSlotListHLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (HLA8.Pkcs11 pkcs11 = new HLA8.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Get all slots
                List<HLA8.Slot> allSlots = pkcs11.GetSlotList(true);
                Assert.IsTrue(allSlots != null && allSlots.Count > 0);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                List<HLA8.Slot> matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == allSlots.Count);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 0);

                // All attributes matching one slot
                HLA8.LibraryInfo libraryInfo = pkcs11.GetInfo();
                HLA8.SlotInfo slotInfo = allSlots[0].GetSlotInfo();
                HLA8.TokenInfo tokenInfo = allSlots[0].GetTokenInfo();

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 0);
            }
        }

        [Test()]
        public void GetMatchingSlotListHLA4()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 4)
                return;

            using (HLA4.Pkcs11 pkcs11 = new HLA4.Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Get all slots
                List<HLA4.Slot> allSlots = pkcs11.GetSlotList(true);
                Assert.IsTrue(allSlots != null && allSlots.Count > 0);

                // Empty URI
                Pkcs11Uri pkcs11uri = new Pkcs11Uri(@"pkcs11:");
                List<HLA4.Slot> matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == allSlots.Count);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 0);

                // All attributes matching one slot
                HLA4.LibraryInfo libraryInfo = pkcs11.GetInfo();
                HLA4.SlotInfo slotInfo = allSlots[0].GetSlotInfo();
                HLA4.TokenInfo tokenInfo = allSlots[0].GetTokenInfo();

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = libraryInfo.ManufacturerId;
                pkcs11UriBuilder.LibraryDescription = libraryInfo.LibraryDescription;
                pkcs11UriBuilder.LibraryVersion = libraryInfo.LibraryVersion;
                pkcs11UriBuilder.SlotManufacturer = slotInfo.ManufacturerId;
                pkcs11UriBuilder.SlotDescription = slotInfo.SlotDescription;
                pkcs11UriBuilder.SlotId = slotInfo.SlotId;
                pkcs11UriBuilder.Token = tokenInfo.Label;
                pkcs11UriBuilder.Manufacturer = tokenInfo.ManufacturerId;
                pkcs11UriBuilder.Serial = tokenInfo.SerialNumber;
                pkcs11UriBuilder.Model = tokenInfo.Model;
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                matchedSlots = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true);
                Assert.IsTrue(matchedSlots.Count == 0);
            }
        }

        [Test()]
        public void GetMatchingSlotListLLA8()
        {
            // Skip test on incompatible platforms
            if (UnmanagedLong.Size != 8)
                return;

            using (LLA8.Pkcs11 pkcs11 = new LLA8.Pkcs11(Settings.Pkcs11LibraryPath, false))
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
                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == allSlots.Length);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 0);

                // All attributes matching one slot
                LLA8.CK_INFO libraryInfo = new LLA8.CK_INFO();
                rv = pkcs11.C_GetInfo(ref libraryInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);
                LLA8.CK_SLOT_INFO slotInfo = new LLA8.CK_SLOT_INFO();
                rv = pkcs11.C_GetSlotInfo(allSlots[0], ref slotInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);
                LLA8.CK_TOKEN_INFO tokenInfo = new LLA8.CK_TOKEN_INFO();
                rv = pkcs11.C_GetTokenInfo(allSlots[0], ref tokenInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
                pkcs11UriBuilder.LibraryDescription = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
                pkcs11UriBuilder.LibraryVersion = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);
                pkcs11UriBuilder.SlotManufacturer = ConvertUtils.BytesToUtf8String(slotInfo.ManufacturerId, true);
                pkcs11UriBuilder.SlotDescription = ConvertUtils.BytesToUtf8String(slotInfo.SlotDescription, true);
                pkcs11UriBuilder.SlotId = allSlots[0];
                pkcs11UriBuilder.Token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
                pkcs11UriBuilder.Manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
                pkcs11UriBuilder.Serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
                pkcs11UriBuilder.Model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
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

            using (LLA4.Pkcs11 pkcs11 = new LLA4.Pkcs11(Settings.Pkcs11LibraryPath, false))
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
                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == allSlots.Length);

                // Unknown path attribute in URI
                pkcs11uri = new Pkcs11Uri(@"pkcs11:vendor=foobar");
                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 0);

                // All attributes matching one slot
                LLA4.CK_INFO libraryInfo = new LLA4.CK_INFO();
                rv = pkcs11.C_GetInfo(ref libraryInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);
                LLA4.CK_SLOT_INFO slotInfo = new LLA4.CK_SLOT_INFO();
                rv = pkcs11.C_GetSlotInfo(allSlots[0], ref slotInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);
                LLA4.CK_TOKEN_INFO tokenInfo = new LLA4.CK_TOKEN_INFO();
                rv = pkcs11.C_GetTokenInfo(allSlots[0], ref tokenInfo);
                Assert.IsTrue(rv == CKR.CKR_OK);

                Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
                pkcs11UriBuilder.LibraryManufacturer = ConvertUtils.BytesToUtf8String(libraryInfo.ManufacturerId, true);
                pkcs11UriBuilder.LibraryDescription = ConvertUtils.BytesToUtf8String(libraryInfo.LibraryDescription, true);
                pkcs11UriBuilder.LibraryVersion = ConvertUtils.CkVersionToString(libraryInfo.LibraryVersion);
                pkcs11UriBuilder.SlotManufacturer = ConvertUtils.BytesToUtf8String(slotInfo.ManufacturerId, true);
                pkcs11UriBuilder.SlotDescription = ConvertUtils.BytesToUtf8String(slotInfo.SlotDescription, true);
                pkcs11UriBuilder.SlotId = allSlots[0];
                pkcs11UriBuilder.Token = ConvertUtils.BytesToUtf8String(tokenInfo.Label, true);
                pkcs11UriBuilder.Manufacturer = ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId, true);
                pkcs11UriBuilder.Serial = ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true);
                pkcs11UriBuilder.Model = ConvertUtils.BytesToUtf8String(tokenInfo.Model, true);
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();

                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 1);

                // One attribute nonmatching
                pkcs11UriBuilder.Serial = "foobar";
                pkcs11uri = pkcs11UriBuilder.ToPkcs11Uri();
                rv = Pkcs11UriUtils.GetMatchingSlotList(pkcs11uri, pkcs11, true, out matchedSlots);
                Assert.IsTrue(rv == CKR.CKR_OK);
                Assert.IsTrue(matchedSlots.Length == 0);

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                Assert.IsTrue(rv == CKR.CKR_OK);
            }
        }

        #endregion

        #endregion

        #region PKCS#11 URI object attributes extraction

        [Test()]
        public void GetObjectAttributesHLA()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            List<HLA.ObjectAttribute> attributes = null;
            Pkcs11UriUtils.GetObjectAttributes(pkcs11uri, out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Count == 3);

            Assert.IsTrue(attributes[0].Type == (ulong)CKA.CKA_CLASS);
            Assert.IsTrue(attributes[0].GetValueAsUlong() == (ulong)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].Type == (ulong)CKA.CKA_LABEL);
            Assert.IsTrue(attributes[1].GetValueAsString() == "foo");

            Assert.IsTrue(attributes[2].Type == (ulong)CKA.CKA_ID);
            Assert.IsTrue(Helpers.ByteArraysMatch(attributes[2].GetValueAsByteArray(), new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesHLA8()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            List<HLA8.ObjectAttribute> attributes = null;
            Pkcs11UriUtils.GetObjectAttributes(pkcs11uri, out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Count == 3);

            Assert.IsTrue(attributes[0].Type == (ulong)CKA.CKA_CLASS);
            Assert.IsTrue(attributes[0].GetValueAsUlong() == (ulong)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].Type == (ulong)CKA.CKA_LABEL);
            Assert.IsTrue(attributes[1].GetValueAsString() == "foo");

            Assert.IsTrue(attributes[2].Type == (ulong)CKA.CKA_ID);
            Assert.IsTrue(Helpers.ByteArraysMatch(attributes[2].GetValueAsByteArray(), new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesHLA4()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            List<HLA4.ObjectAttribute> attributes = null;
            Pkcs11UriUtils.GetObjectAttributes(pkcs11uri, out attributes);

            Assert.IsTrue(attributes != null);
            Assert.IsTrue(attributes.Count == 3);

            Assert.IsTrue(attributes[0].Type == (uint)CKA.CKA_CLASS);
            Assert.IsTrue(attributes[0].GetValueAsUint() == (uint)CKO.CKO_PRIVATE_KEY);

            Assert.IsTrue(attributes[1].Type == (uint)CKA.CKA_LABEL);
            Assert.IsTrue(attributes[1].GetValueAsString() == "foo");

            Assert.IsTrue(attributes[2].Type == (uint)CKA.CKA_ID);
            Assert.IsTrue(Helpers.ByteArraysMatch(attributes[2].GetValueAsByteArray(), new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesLLA8()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            LLA8.CK_ATTRIBUTE[] attributes = null;
            Pkcs11UriUtils.GetObjectAttributes(pkcs11uri, out attributes);

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
            Assert.IsTrue(Helpers.ByteArraysMatch(ckaId, new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test()]
        public void GetObjectAttributesLLA4()
        {
            string uri = @"pkcs11:object=foo;type=private;id=%01%02%03";

            Pkcs11Uri pkcs11uri = new Pkcs11Uri(uri);

            LLA4.CK_ATTRIBUTE[] attributes = null;
            Pkcs11UriUtils.GetObjectAttributes(pkcs11uri, out attributes);

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
            Assert.IsTrue(Helpers.ByteArraysMatch(ckaId, new byte[] { 0x01, 0x02, 0x03 }));
        }

        #endregion
    }
}
