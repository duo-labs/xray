# X-Ray
X-Ray allows you to scan your Android device for security vulnerabilities that put your device at risk.

X-Ray was developed by security researchers at [Duo Security](http://www.duosecurity.com?cid=70170000000sNXI).

We hope that X-Ray will empower users with knowledge of vulnerabilities on their devices and allow them to take action to improve their security.

We encourage users to contact their carriers and ask for their devices to be patched.

## What does X-Ray do?

X-Ray scans your Android device to determine whether there are vulnerabilities that remain unpatched by your carrier. The X-Ray app presents you with a list of vulnerabilities that it is able to identify and allows you to check for the presence of each vulnerability on your device.

X-Ray has detailed knowledge about a class of vulnerabilities known as "privilege escalation" vulnerabilities. Such vulnerabilities can be exploited by a malicious application to gain root privileges on a device and perform actions that would normally be restricted by the Android operating system. A number of such vulnerabilities have been discovered in the core Android platform, affecting nearly all Android devices. Even more have been discovered in manufacturer-specific extensions that may affect a     smaller subset of Android users. Unfortunately, many of these privilege escalation vulnerabilities remain unpatched on large populations of Android devices despite being several years old.

## Why are there unpatched vulnerabilities on my device?

First, the software underlying a modern mobile device is controlled by many parties. Google may be in charge of the base Android Open Source Project, but a typical device includes many different packages, drivers, and customizations from carriers, manufacturers, and other third-parties, not to mention all the open source components (Linux kernel, WebKit, libraries) owned by various project maintainers. When a vulnerability is discovered, coordinating with the responsible parties isn't a trivial task. You'd probably lose if you tried to play Six Degrees of Separation with the developer who introduced the vulnerability, and the party who's responsible for patching it.

Second, carriers can be slow and conservative to supply patches to their users. There is certainly a risk in supplying an update to millions of users, but that doesn't make it acceptable to continue to leave these users exposed to public vulnerabilities for months (or years). The current incentives are flawed: there's little motivation for carriers to put the effort into developing, testing, and deploying a patched version when the latest Android version is sitting on a new device ready for consumers to purchase.

## Is it safe to run X-Ray?

**Absolutely.** Running X-Ray device will have no adverse effects on the security, stability, or performance of your device. X-Ray is installed and run just like any mobile application and requires no special privileges to operate. X-Ray is able to safely probe for the presence of a vulnerability without ever exploiting it.

## What information does X-Ray collect from my device?

**X-Ray collects information about your device, but not about you.**

The collected information serves two purposes:

* to determine whether your device is vulnerable, and
* to collect statistics on just how many Android devices out there are vulnerable

This information is useful to apply pressure on carriers to actually fix the underlying problem, so your participation may end up improving the security of all Android users.

Specifically, X-Ray collects the version of your OS (e.g. `2.3.6`), the make/model of your device (e.g. `Samsung Nexus S`), your carrier's name (e.g. `T-Mobile`), a randomly-generated device ID (eg. `9a17e3fedcde4695`), and potentially vulnerable software components (eg. `/system/bin/vold`). The information collected will not be shared with any third-parties except in aggregate form (eg. a graph showing the total number of vulnerable devices).

## Why is X-Ray not distributed through Google Play Store?

We definitely understand that users prefer to install apps from the Play Store, especially when they're security-related apps. Unfortunately, Google informed us that the terms of service of the Play Store disallow applications such as X-Ray that check for Android vulnerabilities.

## Is X-Ray available for enterprise use?

Yes, the underlying technology that powers X-Ray can be deployed on an enterprise-wide level, giving you global visibility into vulnerabilities affecting your employees' mobile devices. Please contact [xray@duosecurity.com](mailto:xray@duosecurity.com) for more information.

## What's the relation of this project to NowSecure VTS?

We originally wrote X-Ray a few years ago and did not continuously update it with new vulnerabilities.
In late 2015, NowSecure released [Android VTS](https://github.com/nowsecure/android-vts) as an open source project,
which included several vulnerabilities X-Ray didn't test for, as well as a nicer test harness for implementing tests
in a general way.

We decided to collaborate on their testing harness by porting our old tests to run on it, while maintaining and updating
the X-Ray UI, which is targeted more towards average users, as opposed to VTS which targets a technical audience.

We aim to continue adding new vulnerabilities to X-Ray, along with pull requests to VTS so they can include them in their product.

For more details, see [our site](https://labs.duosecurity.com/xray).
