# Linux, Unix, and POSIX: In-Depth

## Origins
If you take into account Android OS (built on Linux), Mac OSX and iOS (Built on Unix), the Windows Linux subsystem, Google Chrome OS (built on Linux), the Linux web infrastructure (LAMP) servers, and the forth coming IoT devices and embedded systems running Linux, \*nix (POSIX) systems running Bash are ubiquitous across the computer industry.

Linux itself is just an Operating System like Windows or OS X. It is the basic platform on which all the other software and programs run.

Linux has its origins in the academic research and student communities. In the early 80's, MS-DOS was available for public use, but it was very expensive. Unix was only licensed to researchers and universities and all operating systems were **closed source**.

**Closed source** means that the general public was not allowed to know how the software work. In other words, they couldn't see it's "source code." However, the hacker/developer/student community wanted to use and learn about computers without paying exorbitant licensing fees. This lead to the development of the `GNU Operating System`.

`GNU` stands for `GNU's not Unix`, and it was meant be a `Unix-Like` operating system that anyone could use for free. `GNU` was started by a Harvard student and hacker named Richard Stallman in 1984.

This kind of software became known as **open source** because anyone can see and modify it's `source` code without paying a licensing fee. To this day, most tools in the hacker/security community are still published as open-source and the idea of free software and free information is very prevalent in the industry.

The `GNU` project eventually created the `Bourne-again Shell`, now known as **Bash**, as an open-source alternative to Unix's `Bourne Shell`. This is the same `Bash` environment that the students have already been using with `git Bash` on windows, and is identical to the OS X Terminal on Apple machines.

By the late 80's, there were so many incompatible operating systems on the market that the `Institute of Electrical and Electronics Engineers` (IEEE) defined an operating system standard based on the most commonly used elements of Unix. Stallman was part of this group and he named it `The Portable Operating System - IX` or `POSIX`. Most \*nix systems still attempt to adhere to the `POSIX` standard which is why learning Linux will also allow you to work on a Unix system.

## POSIX and Interoperability
The idea of using programs together with one another in a command-line shell environment is known as the `Unix Philosophy` and it is part of the `POSIX` standard. Students have already been using the Unix Philosophy by chaining commands together in the command-line.

By 1991, `GNU` was mostly complete, except it didn't yet have an operating system "kernel". The kernel is the most fundamental part of the OS that communicates with the computer's hardware. Without kernel, `GNU` wasn't fully functional.

Enter Linus Torvalds, a computer science student at the University of Helsinki. Linus wasn't part of the `GNU` project, but he also wanted a fully **open source** operating system. He used `GNU`'s open-source developer tools to create the `Linux Kernel`. `Linux` is also a recursive acronym that stands for `Linux is not Unix` and it's also a play on `Linus's` first name.

Linus published his kernel for anyone to use, and it worked well with all of the readily available GNU programs. The Linux kernel, along with the existing programs from the `GNU` project make up what we know today as `Linux`. Because of this, Students may sometimes hear Linux referred to as `GNU/Linux`.

A few years later, in 1993, `Debian` and `RedHat` Linux projects were both started using the `GNU/Linux` combination, or **stack**. These two platforms became the main Linux standards on which almost other versions have been built.

Today, when you choose a version (a.k.a Distribution) of Linux, it will almost always be based on either `Debian` or `RedHat`.

In this course, you'll use `Ubuntu` and `Kali` Linux, both of which are based on `Debian`.

## Linux Distribution Timeline
- Early 80's MS-DOS was too expensive and Unix unavailable to public
- '84 the `GNU` project started as an open source alternative to Unix
- '88 `POSIX` standard was created
- '89 GNU created `BASH`
- '91 Linux Kernel was created
- '93 Debian and Redhat were both released

Once fully functional, Linux quickly became popular among researches and scientists and started to be deployed by companies and even government agencies like NASA. Any organization that wanted to save money on operating costs could find value in a completely free operating system. Today it is used everywhere from IoT devices to servers to cell phones (Android). And Unix is still used on all Apple and iOS systems.

Because Linux was initially made for use with older computers that had limited resources, it did not have a standard desktop and operated only in the command-line. This lends itself well to running command-line only servers, known as **headless servers**. Headless servers are the norm because by today's standards, the CLI requires _very_ little resources. This gives the server maximum resources to run it's services and applications, so a GUI based system is neither required nor desirable.

Being able to navigate a headless Linux server is the main reason why you need to learn Linux and the Bash command line. In addition, learning the Bash command-line environment will enable you to work with both Linux _and_ Unix systems.

This means that, by the end of this module, you'll be proficient with Debian Linux; all of its descendant distributions, such as Ubuntu and Kali; and even Mac OS X.
