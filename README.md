<h1><a href="https://www.enacttrust.com/">
  <img src="https://blog.enacttrust.com/assets/images/logo/enact-logo.png" width="75px" style="vertical-align:middle" style="float:left">
</a>EnactTrust</h1> 

# Security and compliance for IoT & Edge systems

Typical use cases are:
- offline protection of IoT devices in the field
- monitoring of the device health of Edge devices
- compliance for Industrial IoT and Automotive systems

To learn more about EnactTrust, [read our **whitepaper**](https://enact-public.s3.eu-west-1.amazonaws.com/STMicroelectronics+-+EnactTrust+-+Whitepaper+-+Embedded+World+2022.pdf).

## Screenshots

<a href="https://www.enacttrust.com/ew2022"><img alt="Boing Boing" src="https://uploads-ssl.webflow.com/62ac647209e552092604784f/62af56eae7ad8f51ef298187_enact-dashboard-ew2022.png"></a>

Explore device health by visiting the [EnactTrust Security Cloud](https://a3s.enacttrust.com).

## Installation

Please check the [INSTALL.md](INSTALL.md) file for step by step instructions. Short summary is available below:

1. Git clone this repo
1. Make
1. Register at https://a3s.enacttrust.com 
1. enact onboard A3S_USER_ID (see above step)
1. enact

If you're familiar with attestation and are comfortable with looking at C code, you can also try out the [**EnactTrust API**](enact-api.c) which is aimed primarily at 3rd party integrations.

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/6129df878b364f9ca7c09d72ffe852bf)](https://www.codacy.com/gh/EnactTrust/enact/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=EnactTrust/enact&amp;utm_campaign=Badge_Grade)

## Requirements

EnactTrust is built for the *IoT & Edge devices* that live in the field for 3/5/10 years, therefore our implementation is highly portable and EnactTrust supports the most popular firmware architectures. Including the major RTOS solutions, like FreeRTOS, Zephyr and others:

| Architecture          | EnactTrust   | QuickStart   |
| --------------------- | ------------ | ------------ |
| RTOS                  | Yes          |              |
| Bare-metal            | Yes          |              |
| Safety-critical (FSM) | Yes          |              |
| Linux                 | Yes          | Yes          |

Additionally, we aim to support hardware hardening technologies like TrustZone (TF-M & TF-A).

## Built With

The QuickStart version of EnactTrust uses:
- [wolfTPM](https://github.com/wolfssl/wolfTPM) &mdash; Our QuickStart version uses wolfTPM because it is designed for embedded systems and requires no external dependencies.
- [libcurl](https://github.com/curl/curl) &mdash; Our agent uses Curl to communicate easily with our cloud server.

Let us know if you want access to our **TF-M** and TF-A variant of EnactTrust by sending us an [email](mailto:info@enacttrust.com).

## Tiers

This version of EnactTrust is called "Quick Start" and is designed toward ease of use.

Note: EnactTrust is meant to run in a memory isolated environment, so it can protect your system even when your device is compromised or under attack.

Here is the complete list of EnactTrust versions:

*   Quick start - Basic attestation for 1 node (this version).
*   Developer - Advanced attestation for 5 nodes.
*   Enterprise - Protecting IoT products during their entire lifecycle, ZeroTrust security model for critical infrastructure, available on premise and as a managed service, EnactTrust agent deployed in memory isolation to protect the system even in the case of an attack.

## History

The original concept of EnactTrust emerged during 2017 and involves the largest trade fair for "Internet of Things" - Embedded World in Nuremberg/Germany. For the very first time there was a dedicated Trusted Platform Module(TPM) track. Presenters included managers from ARM, OnSemi and other industry leaders. Surprisingly, no one from the five speakers talked about Trusted Computing or mentioned the use of TPM 2.0 modules.

The capability to build trust into a computer system remained just a marketing slogan in 2017. Therefore, in early 2018 we built the first prototype of what later became known as EnactTrust. It took years of development and testing with interested companies to define the core features and qualities of EnactTrust that we have today.

The current "Quick Start" version of EnactTrust is re-written to use the open-source wolfTPM and libcurl librariers, and targets Linux for ease of use.

## Contact us

The goal of [EnactTrust](https://www.enacttrust.com "EnactTrust website") is to make IoT and Edge systems more secure. Send us an [email](mailto:support@enacttrust.com "contact us over email") with your questions and we will respond. Alternatively, you could also use [TPM.dev](https://www.tpm.dev "TPM.dev community forum") forum. 

We look forward to receiving your comments and questions.
