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
 * <a href="http://www.pkcs11interop.net/extensions/uri/">Pkcs11Interop.URI</a> extends Pkcs11Interop with a support for <a href="https://datatracker.ietf.org/doc/draft-pechanec-pkcs11uri/">PKCS#11 URI scheme</a> - an emerging standard for identifying PKCS#11 objects stored in PKCS#11 tokens.
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
 * \section sec_vendor_attrs Vendor specific attributes
 * 
 * Pkcs11Interop.URI introduces following extensions (highlighted with red color) to ABNF specification of PKCS#11 URI scheme:
 * 
<pre>
   pk11-URI            = "pkcs11" ":" pk11-path *1("?" pk11-query)
   ; Path component and its attributes.  Path may be empty.
   pk11-path           = *1(pk11-pattr *(";" pk11-pattr))
   pk11-pattr          = pk11-token / pk11-manuf / pk11-serial /
                         pk11-model / pk11-lib-manuf /
                         pk11-lib-ver / pk11-lib-desc /
                         pk11-object / pk11-type / pk11-id /
                         pk11-x-pattr
   ; Query component and its attributes.  Query may be empty.
   pk11-qattr          = pk11-pin-source / pk11-x-qattr /
                         <b style="color: #ff0000">pk11-x-pin-value / pk11-x-library-path</b>
   pk11-query          = *1(pk11-qattr *("&" pk11-qattr))
   ; RFC 3986 section 2.2 mandates all potentially reserved characters
   ; that do not conflict with actual delimiters of the URI do not have
   ; to be percent-encoded.
   pk11-res-avail =      ":" / "[" / "]" / "@" / "!" / "$" /
                         "'" / "(" / ")" / "*" / "+" / "," / "="
   pk11-path-res-avail = pk11-res-avail / "&"
   ; We allow "/" and "?" in the query to be unencoded but "&" must
   ; be encoded since it may be used as a delimiter in the component.
   pk11-query-res-avail = pk11-res-avail / "/" / "?"
   pk11-pchar          = unreserved / pk11-path-res-avail / pct-encoded
   pk11-qchar          = unreserved / pk11-query-res-avail / pct-encoded
   pk11-token          = "token" "=" *pk11-pchar
   pk11-manuf          = "manufacturer" "=" *pk11-pchar
   pk11-serial         = "serial" "=" *pk11-pchar
   pk11-model          = "model" "=" *pk11-pchar
   pk11-lib-manuf      = "library-manufacturer" "=" *pk11-pchar
   pk11-lib-desc       = "library-description" "=" *pk11-pchar
   pk11-lib-ver        = "library-version" "=" 1*DIGIT *1("." 1*DIGIT)
   pk11-object         = "object" "=" *pk11-pchar
   pk11-type           = "type" "=" *1("public" / "private" / "cert" /
                         "secret-key" / "data")
   pk11-id             = "id" "=" *pk11-pchar
   pk11-pin-source     = "pin-source" "=" *pk11-qchar
   <b style="color: #ff0000">pk11-x-pin-value    = "x-pin-value" "=" *pk11-qchar</b>
   <b style="color: #ff0000">pk11-x-library-path = "x-library-path" "=" 1*pk11-qchar</b>
   pk11-x-attr-nm-char = ALPHA / DIGIT / "-" / "_"
   ; Permitted value of a vendor specific attribute is based on
   ; whether the attribute is used in the path or in the query.
   pk11-x-pattr         = "x-" 1*pk11-x-attr-nm-char "=" *pk11-pchar
   pk11-x-qattr         = "x-" 1*pk11-x-attr-nm-char "=" *pk11-qchar
</pre>
 * 
 * \subsection sec_vendor_attrs_x-pin-value Query attribute "x-pin-value"
 * 
 * The "x-pin-value" attribute represents token PIN. This attribute may be present in the PKCS#11 URI at most once.
 * When both "pin-source" and "x-pin-value" attributes are present in the URI it is up to the URI consumer to decide on how to deal with such situation.
 * Note that an application may always ask for a PIN and/or interpret the "pin-source" and "x-pin-value" attributes by any means it decides to.
 * 
 * <b>Please note that this attribute is a vendor specific attribute and therefore it can be ignored by other PKCS#11 URI implementations.</b>
 * 
 * PKCS#11 URI specification allows "pin-source" attribute to represent a filename that contains a token PIN but it does not allow "pin-source" attribute to specify PIN itself. However it is not unusual for 
 * PKCS#11 URI to be stored in configuration file that is protected by exactly the same mechanisms that protect the file with PIN. In such cases separate file with PIN does not provide security benefits it only 
 * increases application complexity (two files needs to be maintained instead of one). There are also use cases when the fact that key material cannot be exported from secure hardware device is more important 
 * than PIN protection and PIN can be (or needs to be) publicly readable.
 * 
 * This attribute is part of Pkcs11Interop.URI implementation because it is a general purpose library intended to be used by developers who should be able to choose the right tool for the right job and carefully consider 
 * security risks before including PIN in the PKCS#11 URI.
 * 
 * \subsection sec_vendor_attrs_x-library-path Query attribute "x-library-path"
 * 
 * The "x-library-path" attribute specifies name of (or full path to) the PKCS#11 library. This attribute may be present in the PKCS#11 URI at most once.
 * 
 * <b>Please note that this attribute is a vendor specific attribute and therefore it can be ignored by other PKCS#11 URI implementations.</b>
 * 
 * Inclusion of "x-library-path" attribute has been discussed with authors of PKCS#11 URI specification and there has been a mutual agreement that it should not be included in the specification mostly because it is not directly related to the PKCS#11 API. Moreover this attribute can be honored and used only by applications that perform dynamic loading of PKCS#11 libraries (Pkcs11Interop does) and it must be ignored by the applications performing other types of linking.
 * 
 * Despite of described limitations this attribute is part of Pkcs11Interop.URI implementation because it is extremely useful for applications based on Pkcs11Interop and PKCS#11 URI specification allows the existence of such attribute in the statement:
 * <blockquote>If an application has no access to a producer or producers of the PKCS#11 API it is left to its implementation to provide adequate user interface to locate and load such producer(s).</blockquote>
 * The "x-library-path" attribute can be considered to be a specific form of an adequate user interface.
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
 * \example Pkcs11UriExample.cs
 */
