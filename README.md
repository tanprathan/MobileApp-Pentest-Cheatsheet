## Mobile Application Penetration Testing Cheat Sheet


The Mobile App Pentest cheat sheet was created to provide concise collection of high value information on specific mobile application penetration testing topics.

- [All-in-one Mobile Security Frameworks](#all-in-one-mobile-security-frameworks)
- [Android Application Penetration Testing](#android-application-penetration-testing)
  - [Android Testing Distributions](#android-testing-distributions)
  - [Reverse Engineering and Static Analysis](#reverse-engineering-and-static-analysis)
  - [Dynamic and Runtime Analysis](#dynamic-and-runtime-analysis)
  - [Network Analysis and Server Side Testing](#network-analysis-and-server-side-testing)
  - [Bypassing Root Detection and SSL Pinning](#bypassing-root-detection-and-ssl-pinning)
  - [Security Libraries](#security-libraries)
- [iOS Application Penetration Testing](#ios-application-penetration-testing)
  - [Access Filesystem on iDevice](#access-filesystem-on-idevice)
  - [Reverse Engineering and Static Analysis](#reverse-engineering-and-static-analysis)
  - [Dynamic and Runtime Analysis](#dynamic-and-runtime-analysis)
  - [Network Analysis and Server Side Testing](#network-analysis-and-server-side-testing)
  - [Bypassing Root Detection and SSL Pinning](#bypassing-root-detection-and-ssl-pinning)
  - [Security Libraries](#security-libraries)
- [Contribution](#contribution)
- [License](#license)

### All-in-One Mobile Security Frameworks
* [Mobile Security Framework - MobSF](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF) - Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis.
 * python manage.py runserver 127.0.0.1:1337

### Android Application Penetration Testing
#### Android Testing Distributions
* [Appie](https://manifestsecurity.com/appie) - A portable software package for Android Pentesting and an awesome alternative to existing Virtual machines.
* [Android Tamer](https://androidtamer.com/) - Android Tamer is a Virtual / Live Platform for Android Security professionals.
* [AppUse](https://appsec-labs.com/AppUse/) - AppUse is a VM (Virtual Machine) developed by AppSec Labs.
* [Androl4b](https://github.com/sh4hin/Androl4b) - A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis 
* [Mobisec](http://sourceforge.net/projects/mobisec/) - Mobile security testing live environment.
* [Santoku](https://santoku-linux.com/) - Santoku is an OS and can be run outside a VM as a standalone operating system.
#### Reverse Engineering and Static Analysis
* [APKInspector](https://github.com/honeynet/apkinspector/) - APKinspector is a powerful GUI tool for analysts to analyze the Android applications.
* [APKTool](http://ibotpeaches.github.io/Apktool/) - A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications.
 * Disassembling Android apk file
   * apktool d [apk file]
 * Rebuilding decoded resources back to binary APK/JAR with certificate signing
   * apktool b [modified folder]
    * keytool -genkey -v -keystore keys/test.keystore -alias Test -keyalg RSA -keysize 1024 -sigalg SHA1withRSA -validity 10000
    * jarsigner -keystore keys/test.keystore dist/test.apk -sigalg SHA1withRSA -digestalg SHA1 Test
* [Dex2jar](https://github.com/pxb1988/dex2jar) - A tool for converting .dex file to .class files (zipped as jar).
 * Converting apt file into jar file
   * dex2jar [apk file]
* [Oat2dex](https://github.com/testwhat/SmaliEx) - A tool for converting .oat file to .dex files.
 * Deoptimize boot classes (The output will be in "odex" and "dex" folders)
   * java -jar oat2dex.jar boot [boot.oat file]
 * Deoptimize application
   * java -jar oat2dex.jar [app.odex] [boot-class-folder output from above]
 * Get odex from oat
   * java -jar oat2dex.jar odex [oat file]
 * Get odex smali (with optimized opcode) from oat/odex
   * java -jar oat2dex.jar smali [oat/odex file]
* [JD-Gui](http://jd.benow.ca/) - A tool for decompiling and analyzing Java code.
* [FindBugs](http://findbugs.sourceforge.net/) + [FindSecurityBugs](http://h3xstream.github.io/find-sec-bugs/) - FindSecurityBugs is a extension for FindBugs which include security rules for Java applications.
* [Qark](https://github.com/linkedin/qark) - This tool is designed to look for several security related Android application vulnerabilities, either in source code or packaged APKs.
* [AndroBugs] (https://github.com/AndroBugs/AndroBugs_Framework) - AndroBugs Framework is an efficient Android vulnerability scanner that helps developers or hackers find potential security vulnerabilities in Android applications. No need to install on Windows.
* [Simplify](https://github.com/CalebFenton/simplify) - A tool for de-obfuscating android package into Classes.dex which can be use Dex2jar and JD-GUI to extract contents of dex file. 
 * simplify.jar -i [input smali files or folder] -o [output dex file]
* [ClassNameDeobfuscator](https://github.com/HamiltonianCycle/ClassNameDeobfuscator) - Simple script to parse through the .smali files produced by apktool and extract the .source annotation lines.
 
#### Dynamic and Runtime Analysis
* [Introspy-Android](https://github.com/iSECPartners/Introspy-Android) - Blackbox tool to help understand what an Android application is doing at runtime and assist in the identification of potential security issues.
* [Cydia Substrate](http://www.cydiasubstrate.com/) - Cydia Substrate for Android enables developers to make changes to existing software with Substrate extensions that are injected in to the target process's memory.
* [Xposed Framework](http://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053) - Xposed framework enables you to modify the system or application aspect and behaviour at runtime, without modifying any Android application package(APK) or re-flashing.
* [CatLog](https://github.com/nolanlawson/Catlog) - Graphical log reader for Android.
* [Droidbox](https://code.google.com/p/droidbox/) - DroidBox is developed to offer dynamic analysis of Android applications.
* [Frida](http://www.frida.re/) - The toolkit works using a client-server model and lets you inject in to running processes not just on Android, but also on iOS, Windows and Mac.
* [Drozer](https://www.mwrinfosecurity.com/products/drozer/) - Drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.
 * Starting a session
   * adb forward tcp:31415 tcp:31415
    * drozer console connect
 * Retrieving package information
   * run app.package.list -f [app name]
    * run app.package.info -a [package name]
 * Identifying the attack surface
   * run app.package.attacksurface [package name]
 * Exploiting Activities
   * run app.activity.info -a [package name] -u
    * run app.activity.start --component [package name] [component name]
 * Exploiting Content Provider
   * run app.provider.info -a [package name]
    * run scanner.provider.finduris -a [package name]
    * run app.provider.query [uri]
    * run app.provider.update [uri] --selection [conditions] [selection arg] [column] [data]
    * run scanner.provider.sqltables -a [package name]
    * run scanner.provider.injection -a [package name]
    * run scanner.provider.traversal -a [package name]
 * Exploiting Broadcast Receivers
   * run app.broadcast.info -a [package name]
    * run app.broadcast.send --component [package name] [component name] --extra [type] [key] [value]
    * run app.broadcast.sniff --action [action]
 * Exploiting Service
   * run app.service.info -a [package name]
    * run app.service.start --action [action] --component [package name] [component name]
    * run app.service.send [package name] [component name] --msg [what] [arg1] [arg2] --extra [type] [key] [value] --bundle-as-obj

#### Network Analysis and Server Side Testing
* [Tcpdump](http://www.androidtcpdump.com) - A command line packet capture utility.
* [Wireshark](https://www.wireshark.org/download.html) - An open-source packet analyzer.
 * Live packet captures in real time
   * adb shell "tcpdump -s 0 -w - | nc -l -p 4444“
    * adb forward tcp:4444 tcp:4444
    * nc localhost 4444 | sudo wireshark -k -S -i –
* [Canape](http://www.contextis.com/services/research/canape/) - A network testing tool for arbitrary protocols.
* [Mallory](https://intrepidusgroup.com/insight/mallory/) - A Man in The Middle Tool (MiTM) that use to monitor and manipulate traffic on mobile devices and applications.
* [Burp Suite](https://portswigger.net/burp/download.html) - Burp Suite is an integrated platform for performing security testing of applications. 
* [Proxydroid](https://play.google.com/store/apps/details?id=org.proxydroid) - Global Proxy App for Android System.

#### Bypassing Root Detection and SSL Pinning
* [Android SSL Trust Killer](https://github.com/iSECPartners/Android-SSL-TrustKiller) - Blackbox tool to bypass SSL certificate pinning for most applications running on a device.
* [Android-ssl-bypass] (https://github.com/iSECPartners/android-ssl-bypass) - an Android debugging tool that can be used for bypassing SSL, even when certificate pinning is implemented, as well as other debugging tasks. The tool runs as an interactive console.
* [RootCoak Plus](https://github.com/devadvance/rootcloakplus) - Patch root checking for commonly known indications of root.

#### Security Libraries
* [PublicKey Pinning](https://www.owasp.org/images/1/1f/Pubkey-pin-android.zip) - Pinning in Android can be accomplished through a custom X509TrustManager. X509TrustManager should perform the customary X509 checks in addition to performing the pinning configuration.
* [Android Pinning](https://github.com/moxie0/AndroidPinning) - A standalone library project for certificate pinning on Android.
* [Java AES Crypto](https://github.com/tozny/java-aes-crypto) - A simple Android class for encrypting & decrypting strings, aiming to avoid the classic mistakes that most such classes suffer from.
* [Proguard](http://proguard.sourceforge.net/) - ProGuard is a free Java class file shrinker, optimizer, obfuscator, and preverifier. It detects and removes unused classes, fields, methods, and attributes.
* [SQL Cipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/) - SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
* [Secure Preferences](https://github.com/scottyab/secure-preferences) - Android Shared preference wrapper than encrypts the keys and values of Shared Preferences.
* [Trusted Intents](https://github.com/guardianproject/TrustedIntents) - Library for flexible trusted interactions between Android apps.

### iOS Application Penetration Testing
#### Access Filesystem on iDevice
* [FileZilla](https://filezilla-project.org/download.php?show_all=1) -  It supports FTP, SFTP, and FTPS (FTP over SSL/TLS).
* [Cyberduck](https://cyberduck.io) - Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift browser for Mac and Windows.
* [itunnel](https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list) -  Use to forward SSH via USB.
* [iFunbox](http://www.i-funbox.com) - The File and App Management Tool for iPhone, iPad & iPod Touch.

#### Reverse Engineering and Static Analysis
* [otool](http://www.unix.com/man-page/osx/1/otool/) - The otool command displays specified parts of object files or libraries.
* [Clutch](http://cydia.radare.org/) - Decrypted the application and dump specified bundleID into binary or .ipa file. 
* [Dumpdecrypted] (https://github.com/stefanesser/dumpdecrypted) - Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.
  * iPod:~ root# DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/mobile/Applications/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/Scan.app/Scan
* [class-dump](http://stevenygard.com/projects/class-dump/) - A command-line utility for examining the Objective-C runtime information stored in Mach-O files.
* [Weak Classdump] (https://github.com/limneos/weak_classdump) - A Cycript script that generates a header file for the class passed to the function. Most useful when you cannot classdump or dumpdecrypted , when binaries are encrypted etc.
  * iPod:~ root# cycript -p Skype weak_classdump.cy; cycript -p Skype
  * #cy weak_classdump_bundle([NSBundle mainBundle],"/tmp/Skype")
* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml) - IDA is a Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger that offers so many features it is hard to describe them all.
* [HopperApp](http://hopperapp.com/) - Hopper is a reverse engineering tool for OS X and Linux, that lets you disassemble, decompile and debug your 32/64bits Intel Mac, Linux, Windows and iOS executables.
* [iRET](https://www.veracode.com/iret-ios-reverse-engineering-toolkit) - The iOS Reverse Engineering Toolkit is a toolkit designed to automate many of the common tasks associated with iOS penetration testing.
 
#### Dynamic and Runtime Analysis
* [cycript](http://www.cycript.org) - Cycript allows developers to explore and modify running applications on either iOS or Mac OS X using a hybrid of Objective-C++ and JavaScript syntax through an interactive console that features syntax highlighting and tab completion.
  * Show current view
    * cy# UIApp.keyWindow.rootViewController.topViewController.visibleViewController
  * Get an array of existing objects of a certain class
    * cy# choose(UIViewController)
  * List method at runtime
    * cy# [classname].messages  or
    * cy# function printMethods(className) {
  var count = new new Type("I");
  var methods = class_copyMethodList(objc_getClass(className), count);
  var methodsArray = [];
  for(var i = 0; i < *count; i++) {
    var method = methods[i];
    methodsArray.push({selector:method_getName(method), implementation:method_getImplementation(method)});
  }
  free(methods);
  free(count);
  return methodsArray;
}
      * cy# printMethods("[classname]")
  * Prints out all the instance variables
    * cy# function tryPrintIvars(a){ var x={}; for(i in *a){ try{ x[i] = (*a)[i]; } catch(e){} } return x; }
    * cy# a=#0x15d0db80
    * cy# tryPrintIvars(a)
  * Manipulating through property
    * cy# [a pinCode]
    * cy# [a setPinCode: @"1234"]
    * cy# [a isValidPin]
    * cy# a->isa.messages['isValidPin'] = function(){return 1;}
* [iNalyzer](https://appsec-labs.com/cydia/) - AppSec Labs iNalyzer is a framework for manipulating iOS applications, tampering with parameters and method.
* [idb](https://github.com/dmayer/idb) - idb is a tool to simplify some common tasks for iOS pentesting and research.
* [snoop-it](http://cydia.radare.org/) - A tool to assist security assessments and dynamic analysis of iOS Apps.
* [Introspy-iOS](https://github.com/iSECPartners/Introspy-iOS) - Blackbox tool to help understand what an iOS application is doing at runtime and assist in the identification of potential security issues.
* [gdb](http://cydia.radare.org/) - A tool to perform runtime analysis of IOS applications.
* [keychaindumper](http://cydia.radare.org/) - A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken.
* [BinaryCookieReader](http://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py) - A tool to dump all the cookies from the binary Cookies.binarycookies file.

#### Network Analysis and Server Side Testing
* [Canape](http://www.contextis.com/services/research/canape/) - A network testing tool for arbitrary protocols.
* [Mallory](https://intrepidusgroup.com/insight/mallory/) - A Man in The Middle Tool (MiTM) that use to monitor and manipulate traffic on mobile devices and applications.
* [Burp Suite](https://portswigger.net/burp/download.html) - Burp Suite is an integrated platform for performing security testing of applications.
* [Charles Proxy](http://www.charlesproxy.com) - HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet.

#### Bypassing Root Detection and SSL Pinning
* [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) - Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and OS X Apps.
* [iOS TrustMe](https://github.com/intrepidusgroup/trustme) - Disable certificate trust checks on iOS devices.
* [Xcon](http://apt.modmyi.com) - A tool for bypassing Jailbreak detection.
* [tsProtector] (http://cydia.saurik.com/package/kr.typostudio.tsprotector8/) - Another tool for bypassing Jailbreak detection.

#### Security Libraries
* [PublicKey Pinning](https://www.owasp.org/images/9/9a/Pubkey-pin-ios.zip) - iOS pinning is performed through a NSURLConnectionDelegate. The delegate must implement connection:canAuthenticateAgainstProtectionSpace: and connection:didReceiveAuthenticationChallenge:. Within connection:didReceiveAuthenticationChallenge:, the delegate must call SecTrustEvaluate to perform customary X509 checks.

### Contribution
Your contributions and suggestions are welcome.

### License

[![Creative Commons License](http://i.creativecommons.org/l/by/4.0/88x31.png)](http://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/)
