Preparing the testing environment
*********************************

1.  Edit the value of _pkcs11LibraryPath variable in 
    Net.Pkcs11Interop.URI.Tests.Pkcs11UriAndBuilderTest class 
    stored in Pkcs11UriAndBuilderTest.cs file to suit your needs.
2.  Edit PKCS#11 URIs in Pkcs11UriÏnSignatureCreationApplication() method
    of Net.Pkcs11Interop.URI.Tests.Pkcs11UriAndBuilderExample class 
    stored in Pkcs11UriAndBuilderExample.cs file to suit your needs.
3.  Rebuild and run the tests.

Converting NUnit test project to Visual Studio UnitTests
********************************************************

1.  Open "Pkcs11Interop.URI.sln" solution in Visual Studio
2.  Add new "Test project" named "TestProject1" to the solution
3.  Delete automatically created file "UnitTest1.cs" from "TestProject1"
4.  Righ click "TestProject1" project and add reference 
    to "Pkcs11Interop.URI" project  and Pkcs11Interop library
5.  Drag all files from "Pkcs11Interop.URI.Tests" project and drop them 
    into "TestProject1"
6.  Right click "Pkcs11Interop.URI.Tests" project and choose "Unload project" 
    to unload it from solution
7.  Mass replace (CTRL + SHIFT + H) in entire solution:
    using NUnit.Framework;
    to
    using Microsoft.VisualStudio.TestTools.UnitTesting;
8.  Mass replace (CTRL + SHIFT + H) in entire solution:
    [TestFixture()]
    to
    [TestClass]
9.  Mass replace (CTRL + SHIFT + H) in entire solution:
    [Test()]
    to
    [TestMethod]
10. Rebuild solution
