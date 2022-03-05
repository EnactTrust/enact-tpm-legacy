# How to install the "Quick Start" version of EnactTrust

## Requirements

1.  Linux OS

   Debian or Ubuntu is recommended for best experience.

2.  Install wolfssl using

```
./configure --enable-wolftpm --enable-opensslextra --enable-keygen
```

3.  Install wolfTPM using

```
./configure --enable-devtpm
```

4.  Install libcurl

```
apt-get install libcurl
```

## Building

Just run make in the source folder

## Using EnactTrust

Make sure to register at enacttrust.com to receive access to the EnactTrust Security Cloud. Then, launch the agent using:

```
sudo ./enact onboard
```

Once your system is onboarded into the EnactTrust Security Cloud, you could enable regular device health monitoring using:
```
sudo ./enact start
```

Or manually request a fresh evidence from the Enact agent using

```
sudo ./enact
```

## [Questions](mailto:support@enacttrust.com "contact us over email") and comments

[Send us an email](mailto:support@enacttrust.com "contact us over email") and we will respond.
