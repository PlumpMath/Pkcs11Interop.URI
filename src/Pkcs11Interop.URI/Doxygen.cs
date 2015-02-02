/*! \mainpage PKCS#11 URI extensions for Pkcs11Interop library
 * 
 * \tableofcontents
 * 
 * \section sec_overview Overview
 * 
 * <a href="https://www.oasis-open.org/committees/pkcs11/">PKCS#11</a> is cryptography standard originally published by RSA Laboratories that defines ANSI C API to access smart cards and other types of cryptographic hardware. Standard is currently being maintained and developed by the OASIS PKCS 11 Technical Committee.
 * 
 * <a href="http://www.pkcs11interop.net">Pkcs11interop</a> is managed library written in C# that brings full power of PKCS#11 API to the .NET environment. It uses System.Runtime.InteropServices to define platform invoke methods for accessing unmanaged PKCS#11 API and specifies how data is marshaled between managed and unmanaged memory. Pkcs11Interop library supports both 32-bit and 64-bit platforms and can be used with <a href="http://www.microsoft.com/net">.NET Framework</a> 2.0 or higher on Microsoft Windows or with <a href="http://www.mono-project.com/">Mono</a> on Linux, Mac OS X, BSD and others.
 * 
 * <a href="https://github.com/jariq/Pkcs11Interop.URI">Pkcs11Interop.URI</a> extends Pkcs11Interop with a support for <a href="https://datatracker.ietf.org/doc/draft-pechanec-pkcs11uri/">PKCS#11 URI scheme</a> - an emerging standard for identifying PKCS#11 objects stored in PKCS#11 tokens.
 * 
 * \section sec_library_desing Library design
 * 
 * Pkcs11Interop.URI library depends on types from Pkcs11Interop library and contains following important classes:
 * 
 * - Net.Pkcs11Interop.URI.Pkcs11Uri which implements PKCS#11 URI parser
 * - Net.Pkcs11Interop.URI.Pkcs11UriBuilder which implements PKCS#11 URI builder
 * 
 * Before you start using Pkcs11Interop.URI you should be familiar with <a href="http://pkcs11interop.net/doc/">Pkcs11Interop API</a>.
 * 
 * \section sec_code_samples Code samples
 * 
 * Pkcs11Interop.URI source code contains well documented unit tests that also serve as <a href="examples.html">official code samples</a>.
 * 
 * <b>WARNING: Our documentation and code samples do not cover the theory of security/cryptography or the strengths/weaknesses of specific algorithms. You should always understand what you are doing and why. Please do not simply copy our code samples and expect it to fully solve your usage scenario. Cryptography is an advanced topic and one should consult a solid and preferably recent reference in order to make the best of it.</b>
 * 
 * \section sec_more_info More info
 * 
 * Please visit project website - <a class="el" href="http://www.pkcs11interop.net">www.pkcs11interop.net</a> - for more information regarding updates, licensing, support etc.
 */


/*! 
 * \namespace Net.Pkcs11Interop
 * \brief Base namespace of Pkcs11Interop project
 * 
 * \namespace Net.Pkcs11Interop.URI
 * \brief Base namespace of Pkcs11Interop.URI extensions
 */


/*!
 * \example Pkcs11UriAndBuilderExample.cs
 */
